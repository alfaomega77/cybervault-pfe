"""
Train ML models on a labeled dataset, evaluate comparisons, save production models.

Usage:
  cd ai-security-service
  python -m aiss.evaluation.train_models --data /path/to/events.jsonl
  python -m aiss.evaluation.train_models --data events.jsonl --test-ratio 0.3 --seed 42

Expected event format (one JSON object per line or a JSON array):
  {
    "event_type": "command.ingested",
    "timestamp": "2026-07-09T10:00:00+00:00",
    "session_id": "sess-1",
    "user_id": "admin-1",
    "asset_id": "prod-web-1",
    "account": "ubuntu",
    "remote_addr": "203.0.113.10",
    "payload": {"input": "ls -la"},
    "label": 0
  }

label: 0 = normal, 1 = anomaly (required for Random Forest; IF uses normals only).
"""

from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import List, Tuple

from ..config import load_policy, settings
from ..pipeline.behavioral import BaselineStore, BehavioralEngine, combine_assessments
from ..pipeline.dl_gnn import GNNEngine
from ..pipeline.dl_sequence import SequenceDLEngine
from ..pipeline.enrichment import FeatureStore, RulesEngine
from ..pipeline.ml_engine import MLEngine
from ..pipeline.moo_solver import MOOSolver
from ..web.log_analyzer import parse_log_content
from .benchmark import _build_baselines, render_report, run_moo_benchmark
from .metrics import classification_metrics


def load_labeled_events(path: Path) -> List[dict]:
    text = path.read_text(encoding='utf-8')
    events = parse_log_content(text)
    for i, event in enumerate(events):
        if 'label' not in event:
            raise ValueError(
                f'Event #{i+1} missing "label" (0=normal, 1=anomaly). '
                'Add labels to your dataset for supervised training.'
            )
    return events


def split_events(events: List[dict], test_ratio: float, seed: int) -> Tuple[List[dict], List[dict]]:
    import random
    rng = random.Random(seed)
    shuffled = list(events)
    rng.shuffle(shuffled)
    split_at = int(len(shuffled) * (1.0 - test_ratio))
    return shuffled[:split_at], shuffled[split_at:]


def evaluate_on_test(
    test_events: List[dict],
    baselines: BaselineStore,
    model_dir: Path,
    threshold: float = 0.55,
) -> dict:
    policy = load_policy()
    feature_store = FeatureStore(path=str(model_dir / '_eval_features.json'))
    rules = RulesEngine(policy)
    behavioral = BehavioralEngine(policy, store=baselines)
    ml = MLEngine(policy, model_dir=str(model_dir))
    moo = MOOSolver(policy)

    methods = {
        'rules_only': [],
        'ueba_only': [],
        'ml_isolation_forest': [],
        'ml_random_forest': [],
        'dl_sequence': [],
        'dl_gnn': [],
        'hybrid_ensemble': [],
    }
    y_true = [int(e.get('label', 0)) for e in test_events]

    seq = SequenceDLEngine(policy, model_dir=str(model_dir))
    gnn = GNNEngine(policy, model_dir=str(model_dir))

    for event in test_events:
        enriched = feature_store.enrich(event)
        r = rules.score(enriched)
        b = behavioral.score(enriched)
        m = ml.score(enriched)
        s = seq.score(enriched)
        g = gnn.score(enriched)
        hybrid = combine_assessments(r, b, m, s, g, policy=policy)

        methods['rules_only'].append(r['risk_score'])
        methods['ueba_only'].append(b['risk_score'])
        methods['ml_isolation_forest'].append(float(m.get('if_score', 0.0)))
        methods['ml_random_forest'].append(float(m.get('rf_score', 0.0)))
        methods['dl_sequence'].append(s['risk_score'])
        methods['dl_gnn'].append(g['risk_score'])
        methods['hybrid_ensemble'].append(hybrid['risk_score'])

    results = {}
    for name, scores in methods.items():
        y_pred = [1 if s >= threshold else 0 for s in scores]
        results[name] = classification_metrics(y_true, y_pred)

    moo_results = run_moo_benchmark(test_events, baselines)
    return {'detection': results, 'moo': moo_results}


def main():
    parser = argparse.ArgumentParser(description='Train CyberVault ML on your labeled dataset')
    parser.add_argument('--data', required=True, help='Path to .jsonl or .json labeled events')
    parser.add_argument('--model-dir', default=settings.ml_model_dir, help='Where to save .pkl models')
    parser.add_argument('--test-ratio', type=float, default=0.3, help='Fraction held out for evaluation')
    parser.add_argument('--seed', type=int, default=42)
    parser.add_argument('--threshold', type=float, default=0.55)
    parser.add_argument('--output', default='data/research', help='Report directory')
    args = parser.parse_args()

    data_path = Path(args.data)
    if not data_path.exists():
        raise SystemExit(f'Dataset not found: {data_path}')

    model_dir = Path(args.model_dir)
    model_dir.mkdir(parents=True, exist_ok=True)

    events = load_labeled_events(data_path)
    train_events, test_events = split_events(events, args.test_ratio, args.seed)

    print(f'Loaded {len(events)} events → train={len(train_events)} test={len(test_events)}')

    baselines = _build_baselines(train_events)
    baseline_map = {uid: baselines.get(uid) for uid in baselines.users}

    ml = MLEngine(model_dir=str(model_dir))
    labels_train = [int(e.get('label', 0)) for e in train_events]
    train_metrics = ml.train(train_events, labels=labels_train, baselines=baseline_map)
    print(f'Models saved to {model_dir}')
    print(f'  isolation_forest.pkl, random_forest.pkl, training_meta.json')

    seq_meta = SequenceDLEngine(load_policy(), model_dir=str(model_dir)).train(train_events)
    gnn_meta = GNNEngine(load_policy(), model_dir=str(model_dir)).train(train_events)
    print(f"  sequence_dl.pt ({seq_meta.get('architecture')}), gnn_dl.pt")

    eval_results = evaluate_on_test(test_events, baselines, model_dir, args.threshold)

    label_counts = {'normal': sum(1 for e in events if e.get('label') == 0),
                    'anomaly': sum(1 for e in events if e.get('label') == 1)}

    out = Path(args.output)
    out.mkdir(parents=True, exist_ok=True)
    report = render_report(eval_results['detection'], eval_results['moo'], label_counts)
    report_path = out / 'CUSTOM_BENCHMARK_REPORT.md'
    report_path.write_text(report, encoding='utf-8')

    payload = {
        'train': train_metrics,
        'sequence_dl': seq_meta,
        'gnn_dl': gnn_meta,
        'detection': eval_results['detection'],
        'moo': eval_results['moo'],
        'dataset': {'total': len(events), 'train': len(train_events), 'test': len(test_events), **label_counts},
        'model_dir': str(model_dir),
    }
    json_path = out / 'custom_benchmark_results.json'
    json_path.write_text(json.dumps(payload, indent=2), encoding='utf-8')

    print('')
    print('=== Detection comparison (your test set) ===')
    for method, m in eval_results['detection'].items():
        print(f"  {method:22s}  F1={m['f1']:.1%}  Prec={m['precision']:.1%}  "
              f"Rec={m['recall']:.1%}  FPR={m['false_positive_rate']:.1%}")
    print('')
    print(f'Report: {report_path}')
    print(f'JSON:   {json_path}')
    print('')
    print('Next steps:')
    print('  1. Restart web UI / consumer (models auto-load from model-dir)')
    print('  2. Live JumpServer events → dashboard http://localhost:8090/app.html')
    print('  3. Or replay logs → http://localhost:8090/analyze.html')


if __name__ == '__main__':
    main()
