"""
Train deep-learning engines (sequence LSTM/Transformer + privilege GNN).

Usage:
  cd ai-security-service
  python -m aiss.evaluation.train_dl
  python -m aiss.evaluation.train_dl --architecture transformer
  python -m aiss.evaluation.train_dl --data /path/to/events.jsonl
"""

from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Optional, Tuple

from ..config import load_policy, settings
from ..pipeline.dl_gnn import GNNEngine
from ..pipeline.dl_sequence import SequenceDLEngine
from ..web.log_analyzer import parse_log_content
from .dataset import generate_pam_dataset


def load_events(path: Optional[Path], seed: int) -> Tuple[list, dict]:
    if path is None:
        events, counts = generate_pam_dataset(seed=seed)
        return events, counts
    text = path.read_text(encoding='utf-8')
    events = parse_log_content(text)
    for i, ev in enumerate(events):
        if 'label' not in ev:
            raise SystemExit(f'Event #{i+1} missing label (0/1)')
    counts = {
        'normal': sum(1 for e in events if int(e.get('label', 0)) == 0),
        'anomaly': sum(1 for e in events if int(e.get('label', 0)) == 1),
    }
    return events, counts


def main():
    parser = argparse.ArgumentParser(description='Train CyberVault deep-learning models')
    parser.add_argument('--data', default=None, help='Optional labeled .jsonl/.json (else synthetic)')
    parser.add_argument('--model-dir', default=settings.ml_model_dir)
    parser.add_argument('--architecture', choices=['lstm', 'transformer'], default=None)
    parser.add_argument('--seed', type=int, default=42)
    parser.add_argument('--epochs-seq', type=int, default=None)
    parser.add_argument('--epochs-gnn', type=int, default=None)
    parser.add_argument('--skip-gnn', action='store_true')
    parser.add_argument('--skip-sequence', action='store_true')
    parser.add_argument('--output', default='data/research')
    args = parser.parse_args()

    policy = load_policy()
    # allow CLI override of architecture without rewriting YAML permanently
    if args.architecture:
        policy.setdefault('deep_learning', {}).setdefault('sequence', {})['architecture'] = args.architecture

    data_path = Path(args.data) if args.data else None
    events, counts = load_events(data_path, args.seed)
    model_dir = Path(args.model_dir)
    model_dir.mkdir(parents=True, exist_ok=True)

    print(f'Training DL on {len(events)} events → {model_dir}')
    print(f'  label counts: {counts}')

    results = {'dataset': {'total': len(events), **counts}, 'model_dir': str(model_dir)}

    if not args.skip_sequence:
        seq = SequenceDLEngine(policy, model_dir=str(model_dir))
        meta = seq.train(events, epochs=args.epochs_seq)
        results['sequence'] = meta
        print(f"Sequence ({meta.get('architecture')}): samples={meta.get('samples')} "
              f"loss={meta.get('final_loss'):.4f}" if meta.get('final_loss') is not None
              else f"Sequence: {meta}")

    if not args.skip_gnn:
        gnn = GNNEngine(policy, model_dir=str(model_dir))
        meta = gnn.train(events, epochs=args.epochs_gnn)
        results['gnn'] = meta
        print(f"GNN: nodes={meta.get('nodes')} edges={meta.get('edges')} "
              f"loss={meta.get('final_loss'):.4f}" if meta.get('final_loss') is not None
              else f"GNN: {meta}")

    out = Path(args.output)
    out.mkdir(parents=True, exist_ok=True)
    path = out / 'dl_training_results.json'
    path.write_text(json.dumps(results, indent=2), encoding='utf-8')
    print(f'Saved {path}')
    print('Next: python -m aiss.evaluation.demo_sequence_attack')


if __name__ == '__main__':
    main()
