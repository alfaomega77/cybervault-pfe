"""Privilege-graph GNN for relational anomaly scoring.

Builds a heterogeneous user–asset–IP graph from training events and scores
each live event via 2-layer message passing (pure PyTorch, no PyG).
"""

from __future__ import annotations

import json
import logging
from collections import defaultdict
from pathlib import Path
from typing import Dict, List, Optional, Set, Tuple

from ..config import load_policy, settings

logger = logging.getLogger('aiss.dl_gnn')

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


def _node_key(kind: str, value: str) -> str:
    return f'{kind}:{value or "unknown"}'


if TORCH_AVAILABLE:

    class PrivilegeGNN(nn.Module):
        """Simple GraphSAGE-style encoder over undirected privilege graph."""

        def __init__(self, n_nodes: int, emb_dim: int = 32, hidden: int = 64):
            super().__init__()
            self.emb = nn.Embedding(n_nodes, emb_dim)
            self.lin1 = nn.Linear(emb_dim * 2, hidden)
            self.lin2 = nn.Linear(hidden * 2, hidden)
            self.head = nn.Linear(hidden * 3, 1)

        def _aggregate(self, x: 'torch.Tensor', adj: 'torch.Tensor') -> 'torch.Tensor':
            # adj: dense [N, N] normalized
            neigh = adj @ x
            return F.relu(self.lin1(torch.cat([x, neigh], dim=-1)))

        def encode(self, adj: 'torch.Tensor') -> 'torch.Tensor':
            x0 = self.emb.weight
            x1 = self._aggregate(x0, adj)
            neigh = adj @ x1
            x2 = F.relu(self.lin2(torch.cat([x1, neigh], dim=-1)))
            return x2

        def score_triple(self, h: 'torch.Tensor', u: int, a: int, i: int) -> 'torch.Tensor':
            vec = torch.cat([h[u], h[a], h[i]], dim=-1)
            return torch.sigmoid(self.head(vec).squeeze(-1))

else:
    PrivilegeGNN = None  # type: ignore


class GraphIndex:
    def __init__(self):
        self.node_to_id: Dict[str, int] = {}
        self.edges: Set[Tuple[int, int]] = set()

    def add_node(self, key: str) -> int:
        if key not in self.node_to_id:
            self.node_to_id[key] = len(self.node_to_id)
        return self.node_to_id[key]

    def add_edge(self, a: int, b: int):
        if a == b:
            return
        self.edges.add((min(a, b), max(a, b)))

    def to_dict(self) -> dict:
        return {
            'node_to_id': self.node_to_id,
            'edges': [[a, b] for a, b in sorted(self.edges)],
        }

    @classmethod
    def from_dict(cls, data: dict) -> 'GraphIndex':
        g = cls()
        g.node_to_id = {k: int(v) for k, v in (data.get('node_to_id') or {}).items()}
        for a, b in data.get('edges') or []:
            g.edges.add((int(a), int(b)))
        return g


def _event_nodes(event: dict) -> Tuple[str, str, str]:
    user = event.get('user_id') or 'unknown'
    asset = event.get('asset_id') or 'unknown'
    ip = event.get('remote_addr') or (event.get('features') or {}).get('remote_addr') or 'unknown'
    return user, asset, ip


class GNNEngine:
    """Relational privilege-graph anomaly scorer."""

    def __init__(self, policy: Optional[dict] = None, model_dir: Optional[str] = None):
        self.policy = policy or load_policy()
        self.cfg = (self.policy.get('deep_learning') or {}).get('gnn', {})
        self.model_dir = Path(model_dir or settings.ml_model_dir)
        self.model_dir.mkdir(parents=True, exist_ok=True)
        self.graph = GraphIndex()
        self.model = None
        self._adj = None
        self._load()

    @property
    def enabled(self) -> bool:
        return bool(self.cfg.get('enabled', True)) and TORCH_AVAILABLE

    def _paths(self) -> Dict[str, Path]:
        return {
            'model': self.model_dir / 'gnn_dl.pt',
            'meta': self.model_dir / 'gnn_dl_meta.json',
        }

    def _build_graph_from_events(self, events: List[dict]) -> GraphIndex:
        g = GraphIndex()
        for ev in events:
            user, asset, ip = _event_nodes(ev)
            u = g.add_node(_node_key('user', user))
            a = g.add_node(_node_key('asset', asset))
            i = g.add_node(_node_key('ip', ip))
            g.add_edge(u, a)
            g.add_edge(u, i)
            g.add_edge(a, i)
        # ensure unknown nodes exist for OOV at inference
        g.add_node(_node_key('user', 'unknown'))
        g.add_node(_node_key('asset', 'unknown'))
        g.add_node(_node_key('ip', 'unknown'))
        return g

    def _adjacency(self, graph: GraphIndex) -> 'torch.Tensor':
        n = len(graph.node_to_id)
        adj = torch.zeros(n, n)
        for a, b in graph.edges:
            adj[a, b] = 1.0
            adj[b, a] = 1.0
        # self-loops
        adj += torch.eye(n)
        deg = adj.sum(dim=1, keepdim=True).clamp(min=1.0)
        return adj / deg

    def _resolve(self, kind: str, value: str) -> int:
        key = _node_key(kind, value)
        if key in self.graph.node_to_id:
            return self.graph.node_to_id[key]
        return self.graph.node_to_id[_node_key(kind, 'unknown')]

    def _load(self):
        if not self.enabled:
            return
        paths = self._paths()
        if not paths['model'].exists() or not paths['meta'].exists():
            return
        try:
            meta = json.loads(paths['meta'].read_text(encoding='utf-8'))
            self.graph = GraphIndex.from_dict(meta['graph'])
            emb = int(meta.get('emb_dim', self.cfg.get('emb_dim', 32)))
            hidden = int(meta.get('hidden', self.cfg.get('hidden', 64)))
            self.model = PrivilegeGNN(len(self.graph.node_to_id), emb_dim=emb, hidden=hidden)
            self.model.load_state_dict(torch.load(paths['model'], map_location='cpu'))
            self.model.eval()
            self._adj = self._adjacency(self.graph)
            logger.info('Loaded privilege GNN (%d nodes)', len(self.graph.node_to_id))
        except Exception as exc:  # noqa: BLE001
            logger.warning('Failed to load GNN: %s', exc)
            self.model = None

    def train(
        self,
        events: List[dict],
        epochs: Optional[int] = None,
        lr: float = 1e-3,
    ) -> Dict[str, object]:
        if not TORCH_AVAILABLE:
            raise RuntimeError('PyTorch required: pip install torch')

        self.graph = self._build_graph_from_events(events)
        emb = int(self.cfg.get('emb_dim', 32))
        hidden = int(self.cfg.get('hidden', 64))
        self.model = PrivilegeGNN(len(self.graph.node_to_id), emb_dim=emb, hidden=hidden)
        self._adj = self._adjacency(self.graph)

        triples = []
        labels = []
        for ev in events:
            user, asset, ip = _event_nodes(ev)
            u = self._resolve('user', user)
            a = self._resolve('asset', asset)
            i = self._resolve('ip', ip)
            triples.append((u, a, i))
            labels.append(int(ev.get('label', 0)))

        y = torch.tensor(labels, dtype=torch.float32)
        pos = max(float((y == 1).sum()), 1.0)
        neg = max(float((y == 0).sum()), 1.0)
        pos_weight = neg / pos

        opt = torch.optim.Adam(self.model.parameters(), lr=lr)
        n_epochs = int(epochs if epochs is not None else self.cfg.get('epochs', 20))
        losses = []
        self.model.train()

        for _ in range(n_epochs):
            h = self.model.encode(self._adj)
            preds = []
            for u, a, i in triples:
                preds.append(self.model.score_triple(h, u, a, i))
            pred = torch.stack(preds)
            weights = torch.where(y > 0.5, torch.full_like(y, pos_weight), torch.ones_like(y))
            loss = F.binary_cross_entropy(pred, y, weight=weights)
            opt.zero_grad()
            loss.backward()
            opt.step()
            losses.append(float(loss.item()))

        self.model.eval()
        paths = self._paths()
        torch.save(self.model.state_dict(), paths['model'])
        meta = {
            'graph': self.graph.to_dict(),
            'emb_dim': emb,
            'hidden': hidden,
            'samples': len(triples),
            'nodes': len(self.graph.node_to_id),
            'edges': len(self.graph.edges),
            'final_loss': losses[-1] if losses else None,
            'epochs': n_epochs,
        }
        paths['meta'].write_text(json.dumps(meta, indent=2), encoding='utf-8')
        self._adj = self._adjacency(self.graph)
        return meta

    def score(self, event: dict) -> dict:
        if not self.enabled:
            return self._empty('dl_gnn_disabled')
        if self.model is None or self._adj is None:
            return self._empty('dl_gnn_not_trained')

        user, asset, ip = _event_nodes(event)
        u = self._resolve('user', user)
        a = self._resolve('asset', asset)
        i = self._resolve('ip', ip)

        with torch.no_grad():
            h = self.model.encode(self._adj)
            risk = float(self.model.score_triple(h, u, a, i).item())

        reasons = [f'nodes:user={user}', f'asset={asset}', f'ip={ip}']
        # novelty hints when mapped to unknown
        if _node_key('asset', asset) not in self.graph.node_to_id:
            reasons.append('oov_asset')
        if _node_key('ip', ip) not in self.graph.node_to_id:
            reasons.append('oov_ip')

        return {
            'risk_score': min(max(risk, 0.0), 1.0),
            'confidence': 0.75 if risk >= 0.55 else 0.55,
            'reasons': reasons,
            'model': 'dl_gnn_privilege',
        }

    def _empty(self, reason: str) -> dict:
        return {
            'risk_score': 0.0,
            'confidence': 0.0,
            'reasons': [reason],
            'model': 'dl_gnn_none',
        }
