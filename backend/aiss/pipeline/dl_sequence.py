"""Deep-learning sequence models for progressive privileged-command attacks.

Implements LSTM and Transformer encoders over session command history.
Scores r_S(e) from H_s = (c_1, ..., c_t) and integrates via max-fusion.
"""

from __future__ import annotations

import json
import logging
import re
from collections import Counter
from pathlib import Path
from typing import Dict, List, Optional, Sequence, Tuple

from ..config import load_policy, settings

logger = logging.getLogger('aiss.dl_sequence')

try:
    import torch
    import torch.nn as nn
    import torch.nn.functional as F
    TORCH_AVAILABLE = True
except ImportError:
    torch = None  # type: ignore
    nn = None  # type: ignore
    F = None  # type: ignore
    TORCH_AVAILABLE = False

TOKEN_RE = re.compile(r"[a-zA-Z0-9_./:@*-]+")
PAD, UNK, CLS = '<pad>', '<unk>', '<cls>'


def tokenize_command(command: str) -> List[str]:
    return [t.lower() for t in TOKEN_RE.findall(command or '')]


class CommandVocab:
    def __init__(self, token_to_id: Optional[Dict[str, int]] = None, max_size: int = 4000):
        self.max_size = max_size
        if token_to_id:
            self.token_to_id = dict(token_to_id)
        else:
            self.token_to_id = {PAD: 0, UNK: 1, CLS: 2}

    def fit(self, commands: Sequence[str]) -> 'CommandVocab':
        counts: Counter = Counter()
        for cmd in commands:
            counts.update(tokenize_command(cmd))
        for tok, _ in counts.most_common(self.max_size - len(self.token_to_id)):
            if tok not in self.token_to_id:
                self.token_to_id[tok] = len(self.token_to_id)
        return self

    def encode_command(self, command: str, max_tokens: int = 24) -> List[int]:
        ids = [self.token_to_id.get(t, self.token_to_id[UNK]) for t in tokenize_command(command)]
        if not ids:
            ids = [self.token_to_id[UNK]]
        ids = ids[:max_tokens]
        if len(ids) < max_tokens:
            ids = ids + [self.token_to_id[PAD]] * (max_tokens - len(ids))
        return ids

    def to_dict(self) -> dict:
        return {'token_to_id': self.token_to_id, 'max_size': self.max_size}

    @classmethod
    def from_dict(cls, data: dict) -> 'CommandVocab':
        return cls(token_to_id=data.get('token_to_id'), max_size=int(data.get('max_size', 4000)))


if TORCH_AVAILABLE:

    class SequenceLSTM(nn.Module):
        def __init__(self, vocab_size: int, emb_dim: int = 64, hidden: int = 64, max_tokens: int = 24):
            super().__init__()
            self.max_tokens = max_tokens
            self.emb = nn.Embedding(vocab_size, emb_dim, padding_idx=0)
            self.lstm = nn.LSTM(emb_dim, hidden, batch_first=True, bidirectional=True)
            self.head = nn.Linear(hidden * 2, 1)

        def forward(self, x: 'torch.Tensor') -> 'torch.Tensor':
            # x: [B, S, T]
            b, s, t = x.shape
            flat = x.view(b * s, t)
            emb = self.emb(flat)  # [B*S, T, E]
            mask = (flat != 0).float().unsqueeze(-1)
            pooled = (emb * mask).sum(dim=1) / mask.sum(dim=1).clamp(min=1.0)
            cmd = pooled.view(b, s, -1)
            out, _ = self.lstm(cmd)
            logits = self.head(out[:, -1, :]).squeeze(-1)
            return torch.sigmoid(logits)

    class SequenceTransformer(nn.Module):
        def __init__(
            self,
            vocab_size: int,
            emb_dim: int = 64,
            nhead: int = 4,
            nlayers: int = 2,
            max_tokens: int = 24,
            max_seq: int = 16,
        ):
            super().__init__()
            self.max_tokens = max_tokens
            self.emb = nn.Embedding(vocab_size, emb_dim, padding_idx=0)
            self.pos = nn.Parameter(torch.zeros(1, max_seq, emb_dim))
            encoder_layer = nn.TransformerEncoderLayer(
                d_model=emb_dim, nhead=nhead, dim_feedforward=emb_dim * 2,
                batch_first=True, dropout=0.1,
            )
            self.encoder = nn.TransformerEncoder(encoder_layer, num_layers=nlayers)
            self.head = nn.Linear(emb_dim, 1)

        def forward(self, x: 'torch.Tensor') -> 'torch.Tensor':
            b, s, t = x.shape
            flat = x.view(b * s, t)
            emb = self.emb(flat)
            mask = (flat != 0).float().unsqueeze(-1)
            pooled = (emb * mask).sum(dim=1) / mask.sum(dim=1).clamp(min=1.0)
            cmd = pooled.view(b, s, -1) + self.pos[:, :s, :]
            pad_cmd = (x.sum(dim=-1) == 0)  # [B, S]
            encoded = self.encoder(cmd, src_key_padding_mask=pad_cmd)
            # use last non-pad command
            lengths = (~pad_cmd).sum(dim=1).clamp(min=1) - 1
            idx = lengths.view(b, 1, 1).expand(-1, 1, encoded.size(-1))
            last = encoded.gather(1, idx).squeeze(1)
            return torch.sigmoid(self.head(last).squeeze(-1))


else:
    SequenceLSTM = None  # type: ignore
    SequenceTransformer = None  # type: ignore


def _session_commands(event: dict) -> List[str]:
    features = event.get('features') or {}
    recent = features.get('recent_commands') or []
    if recent:
        return [str(c) for c in recent if c]
    cmd = (event.get('payload') or {}).get('input', '') or ''
    return [cmd] if cmd else []


def build_sequence_samples(
    events: List[dict],
    max_seq: int = 16,
) -> Tuple[List[List[str]], List[int]]:
    """Build (command history, label) samples from labeled events grouped by session."""
    by_session: Dict[str, List[dict]] = {}
    for ev in events:
        sid = ev.get('session_id') or 'unknown'
        by_session.setdefault(sid, []).append(ev)

    histories: List[List[str]] = []
    labels: List[int] = []
    for sid, items in by_session.items():
        items = sorted(items, key=lambda e: e.get('timestamp') or '')
        running: List[str] = []
        for ev in items:
            cmd = (ev.get('payload') or {}).get('input', '') or ''
            if cmd:
                running.append(cmd)
            hist = running[-max_seq:]
            if not hist:
                continue
            histories.append(list(hist))
            labels.append(int(ev.get('label', 0)))
    return histories, labels


class SequenceDLEngine:
    """Session-sequence anomaly scorer (LSTM or Transformer)."""

    def __init__(self, policy: Optional[dict] = None, model_dir: Optional[str] = None):
        self.policy = policy or load_policy()
        self.cfg = (self.policy.get('deep_learning') or {}).get('sequence', {})
        self.model_dir = Path(model_dir or settings.ml_model_dir)
        self.model_dir.mkdir(parents=True, exist_ok=True)
        self.vocab: Optional[CommandVocab] = None
        self.model = None
        self.architecture = self.cfg.get('architecture', 'lstm')
        self.max_seq = int(self.cfg.get('max_seq', 16))
        self.max_tokens = int(self.cfg.get('max_tokens', 24))
        self.device = 'cpu'
        self._load()

    @property
    def enabled(self) -> bool:
        return bool(self.cfg.get('enabled', True)) and TORCH_AVAILABLE

    def _paths(self) -> Dict[str, Path]:
        return {
            'model': self.model_dir / 'sequence_dl.pt',
            'meta': self.model_dir / 'sequence_dl_meta.json',
        }

    def _build_model(self, vocab_size: int):
        arch = self.architecture
        emb = int(self.cfg.get('emb_dim', 64))
        hidden = int(self.cfg.get('hidden', 64))
        if arch == 'transformer':
            return SequenceTransformer(
                vocab_size, emb_dim=emb, nhead=int(self.cfg.get('nhead', 4)),
                nlayers=int(self.cfg.get('nlayers', 2)),
                max_tokens=self.max_tokens, max_seq=self.max_seq,
            )
        return SequenceLSTM(vocab_size, emb_dim=emb, hidden=hidden, max_tokens=self.max_tokens)

    def _encode_batch(self, histories: List[List[str]]) -> 'torch.Tensor':
        assert self.vocab is not None
        batch = []
        for hist in histories:
            hist = hist[-self.max_seq:]
            rows = [self.vocab.encode_command(c, self.max_tokens) for c in hist]
            while len(rows) < self.max_seq:
                rows.insert(0, [0] * self.max_tokens)
            batch.append(rows[-self.max_seq:])
        return torch.tensor(batch, dtype=torch.long)

    def _load(self):
        if not self.enabled:
            return
        paths = self._paths()
        if not paths['model'].exists() or not paths['meta'].exists():
            return
        try:
            meta = json.loads(paths['meta'].read_text(encoding='utf-8'))
            self.vocab = CommandVocab.from_dict(meta['vocab'])
            self.architecture = meta.get('architecture', self.architecture)
            self.max_seq = int(meta.get('max_seq', self.max_seq))
            self.max_tokens = int(meta.get('max_tokens', self.max_tokens))
            self.model = self._build_model(len(self.vocab.token_to_id))
            state = torch.load(paths['model'], map_location='cpu')
            self.model.load_state_dict(state)
            self.model.eval()
            logger.info('Loaded sequence DL model (%s)', self.architecture)
        except Exception as exc:  # noqa: BLE001
            logger.warning('Failed to load sequence DL: %s', exc)
            self.model = None

    def train(
        self,
        events: List[dict],
        epochs: Optional[int] = None,
        lr: float = 1e-3,
    ) -> Dict[str, object]:
        if not TORCH_AVAILABLE:
            raise RuntimeError('PyTorch required: pip install torch')

        histories, labels = build_sequence_samples(events, max_seq=self.max_seq)
        if not histories:
            raise ValueError('No command sequences found for DL training')

        all_cmds = [c for h in histories for c in h]
        self.vocab = CommandVocab(max_size=int(self.cfg.get('vocab_size', 4000))).fit(all_cmds)
        self.model = self._build_model(len(self.vocab.token_to_id))
        self.model.train()

        X = self._encode_batch(histories)
        y = torch.tensor(labels, dtype=torch.float32)
        # class imbalance
        pos = max(float((y == 1).sum()), 1.0)
        neg = max(float((y == 0).sum()), 1.0)
        pos_weight = torch.tensor([neg / pos])

        opt = torch.optim.Adam(self.model.parameters(), lr=lr)
        n_epochs = int(epochs if epochs is not None else self.cfg.get('epochs', 12))
        batch_size = int(self.cfg.get('batch_size', 64))
        losses = []

        for epoch in range(n_epochs):
            perm = torch.randperm(len(y))
            epoch_loss = 0.0
            n_batches = 0
            for start in range(0, len(y), batch_size):
                idx = perm[start:start + batch_size]
                xb, yb = X[idx], y[idx]
                pred = self.model(xb)
                sample_w = torch.where(yb > 0.5, pos_weight, torch.ones_like(yb))
                loss = F.binary_cross_entropy(pred, yb, weight=sample_w)
                opt.zero_grad()
                loss.backward()
                opt.step()
                epoch_loss += float(loss.item())
                n_batches += 1
            losses.append(epoch_loss / max(n_batches, 1))

        self.model.eval()
        paths = self._paths()
        torch.save(self.model.state_dict(), paths['model'])
        meta = {
            'architecture': self.architecture,
            'vocab': self.vocab.to_dict(),
            'max_seq': self.max_seq,
            'max_tokens': self.max_tokens,
            'samples': len(histories),
            'positives': int(pos),
            'negatives': int(neg),
            'final_loss': losses[-1] if losses else None,
            'epochs': n_epochs,
        }
        paths['meta'].write_text(json.dumps(meta, indent=2), encoding='utf-8')
        return meta

    def score(self, event: dict) -> dict:
        if not self.enabled:
            return self._empty('dl_sequence_disabled')
        if self.model is None or self.vocab is None:
            return self._empty('dl_sequence_not_trained')

        commands = _session_commands(event)
        if not commands:
            return self._empty('dl_sequence_no_commands')

        with torch.no_grad():
            x = self._encode_batch([commands])
            raw = float(self.model(x)[0].item())

        # Temperature calibration (>1 softens overconfident scores)
        temperature = float(self.cfg.get('temperature', 1.5))
        if temperature != 1.0 and 0.0 < raw < 1.0:
            import math
            logit = math.log(raw / (1.0 - raw))
            risk = 1.0 / (1.0 + math.exp(-logit / temperature))
        else:
            risk = raw

        # Mild length prior: longer progressive chains get a small boost already learned;
        # expose stage hints for analysts.
        text = ' '.join(commands).lower()
        reasons = [f'seq_len:{len(commands)}', f'arch:{self.architecture}']
        for hint, keys in [
            ('recon_tokens', ('find', 'pem', 'id_rsa', 'passwd')),
            ('pivot_tokens', ('ssh', 'scp', 'prod-db')),
            ('exfil_tokens', ('tar', 'curl', 'wget', 'nc ')),
        ]:
            if any(k in text for k in keys):
                reasons.append(hint)

        return {
            'risk_score': min(max(risk, 0.0), 1.0),
            'confidence': 0.8 if risk >= 0.55 else 0.6,
            'reasons': reasons,
            'model': f'dl_sequence_{self.architecture}',
            'sequence_length': len(commands),
        }

    def _empty(self, reason: str) -> dict:
        return {
            'risk_score': 0.0,
            'confidence': 0.0,
            'reasons': [reason],
            'model': 'dl_sequence_none',
        }
