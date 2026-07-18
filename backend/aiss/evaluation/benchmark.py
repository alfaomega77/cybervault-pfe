"""Comparative benchmark: rules vs UEBA vs ML vs hybrid vs MOO."""

import json
from pathlib import Path
from typing import Dict, List, Tuple

from ..config import load_policy
from ..features.extractor import extract_feature_vector
from ..pipeline.behavioral import BaselineStore, BehavioralEngine, UserBaseline, combine_assessments
from ..pipeline.dl_gnn import GNNEngine
from ..pipeline.dl_sequence import SequenceDLEngine
from ..pipeline.enrichment import FeatureStore, RulesEngine
from ..pipeline.ml_engine import MLEngine
from ..pipeline.moo_solver import MOOSolver
from .dataset import generate_pam_dataset
from .metrics import classification_metrics, disruption_cost, markdown_table


def _build_baselines(train_events: List[dict]) -> BaselineStore:
    path = Path('/tmp/aiss_benchmark_baselines.json')
    if path.exists():
        path.unlink()
    store = BaselineStore(path=str(path))
    engine = BehavioralEngine(store=store)
    for event in train_events:
        if event.get('label', 0) == 0:
            enriched = dict(event)
            enriched['features'] = {
                'hour_utc': int(event.get('timestamp', 'T10:')[11:13] or 10),
                'session_command_count': 5,
                'user_total_commands': 20,
                'is_acl_violation': False,
            }
            engine.learn(enriched, 0.0)
    return store


def _enrich_event(event: dict, feature_store: FeatureStore) -> dict:
    return feature_store.enrich(event)


def _score_threshold(risk: float, threshold: float = 0.55) -> int:
    return 1 if risk >= threshold else 0


def run_detection_benchmark(
    threshold: float = 0.55,
    seed: int = 42,
) -> Tuple[Dict[str, dict], List[dict], List[dict]]:
    policy = load_policy()
    events, counts = generate_pam_dataset(seed=seed)
    split = int(len(events) * 0.7)
    train_events = events[:split]
    test_events = events[split:]

    baselines = _build_baselines(train_events)
    feature_store = FeatureStore(path=str(Path('/tmp/aiss_benchmark_features.json')))

    rules = RulesEngine(policy)
    behavioral = BehavioralEngine(policy, store=baselines)
    model_dir = Path('/tmp/aiss_benchmark_models')
    ml = MLEngine(policy, model_dir=str(model_dir))
    seq = SequenceDLEngine(policy, model_dir=str(model_dir))
    gnn = GNNEngine(policy, model_dir=str(model_dir))

    labels_train = [e.get('label', 0) for e in train_events]
    baseline_map = {uid: baselines.get(uid) for uid in baselines.users}
    ml.train(train_events, labels=labels_train, baselines=baseline_map)
    seq.train(train_events)
    gnn.train(train_events)

    methods = {
        'rules_only': [],
        'ueba_only': [],
        'ml_isolation_forest': [],
        'ml_random_forest': [],
        'dl_sequence': [],
        'dl_gnn': [],
        'hybrid_ensemble': [],
    }
    risks = {k: [] for k in methods}
    y_true = [e.get('label', 0) for e in test_events]

    for event in test_events:
        enriched = _enrich_event(event, feature_store)
        r = rules.score(enriched)
        b = behavioral.score(enriched)
        m = ml.score(enriched)
        s = seq.score(enriched)
        g = gnn.score(enriched)

        risks['rules_only'].append(r['risk_score'])
        risks['ueba_only'].append(b['risk_score'])
        risks['ml_isolation_forest'].append(float(m.get('if_score', 0.0)))
        risks['ml_random_forest'].append(float(m.get('rf_score', 0.0)))
        risks['dl_sequence'].append(s['risk_score'])
        risks['dl_gnn'].append(g['risk_score'])
        hybrid = combine_assessments(r, b, m, s, g, policy=policy)
        risks['hybrid_ensemble'].append(hybrid['risk_score'])

    results = {}
    for name, scores in risks.items():
        y_pred = [_score_threshold(s, threshold) for s in scores]
        results[name] = classification_metrics(y_true, y_pred)

    return results, train_events, test_events


def run_moo_benchmark(test_events: List[dict], baselines: BaselineStore) -> Dict[str, dict]:
    policy = load_policy()
    rules = RulesEngine(policy)
    behavioral = BehavioralEngine(policy, store=baselines)
    model_dir = Path('/tmp/aiss_benchmark_models')
    ml = MLEngine(policy, model_dir=str(model_dir))
    seq = SequenceDLEngine(policy, model_dir=str(model_dir))
    gnn = GNNEngine(policy, model_dir=str(model_dir))
    moo = MOOSolver(policy)
    feature_store = FeatureStore(path=str(Path('/tmp/aiss_benchmark_features2.json')))

    threshold_actions: List[str] = []
    moo_actions: List[str] = []
    labels: List[int] = []

    for event in test_events:
        enriched = feature_store.enrich(event)
        assessment = combine_assessments(
            rules.score(enriched),
            behavioral.score(enriched),
            ml.score(enriched),
            seq.score(enriched),
            gnn.score(enriched),
            policy=policy,
        )
        risk = assessment['risk_score']
        label = event.get('label', 0)
        labels.append(label)

        if risk >= 0.55:
            threshold_actions.append('ALERT_ANALYST')
        else:
            threshold_actions.append('NO_ACTION')

        decision = moo.decide(enriched, assessment)
        moo_actions.append(decision['action'])

    return {
        'threshold_policy': {
            **disruption_cost(threshold_actions, labels),
            **classification_metrics(
                labels,
                [1 if a != 'NO_ACTION' else 0 for a in threshold_actions],
            ),
        },
        'moo_policy': {
            **disruption_cost(moo_actions, labels),
            **classification_metrics(
                labels,
                [1 if a not in ('NO_ACTION', 'LOG_ONLY') else 0 for a in moo_actions],
            ),
        },
    }


def render_report(
    detection_results: Dict[str, dict],
    moo_results: Dict[str, dict],
    dataset_counts: dict,
) -> str:
    det_rows = []
    for method, metrics in detection_results.items():
        det_rows.append([
            method,
            f"{metrics['accuracy']:.1%}",
            f"{metrics['precision']:.1%}",
            f"{metrics['recall']:.1%}",
            f"{metrics['f1']:.1%}",
            f"{metrics['false_positive_rate']:.1%}",
        ])

    moo_rows = []
    for policy_name, metrics in moo_results.items():
        moo_rows.append([
            policy_name,
            f"{metrics.get('false_disruption_rate', 0):.1%}",
            f"{metrics.get('missed_threat_rate', 0):.1%}",
            f"{metrics.get('f1', 0):.1%}",
        ])

    dataset_rows = [[k, str(v)] for k, v in dataset_counts.items()]

    return '\n\n'.join([
        '# PAM AI Security — Benchmark Report',
        '## Dataset composition',
        markdown_table(['Class', 'Count'], dataset_rows),
        '## Detection model comparison (threshold=0.55)',
        markdown_table(
            ['Method', 'Accuracy', 'Precision', 'Recall', 'F1', 'FPR'],
            det_rows,
        ),
        '## Operations Research — response policy comparison',
        markdown_table(
            ['Policy', 'False disruption rate', 'Missed threat rate', 'F1 (alert+)'],
            moo_rows,
        ),
    ])


def run_full_benchmark(output_dir: str, seed: int = 42) -> Path:
    out = Path(output_dir)
    out.mkdir(parents=True, exist_ok=True)

    detection_results, train_events, test_events = run_detection_benchmark(seed=seed)
    _, counts = generate_pam_dataset(seed=seed)
    baselines = _build_baselines(train_events)
    moo_results = run_moo_benchmark(test_events, baselines)

    report = render_report(detection_results, moo_results, counts)
    report_path = out / 'BENCHMARK_REPORT.md'
    report_path.write_text(report, encoding='utf-8')

    payload = {
        'detection': detection_results,
        'moo': moo_results,
        'dataset': counts,
    }
    (out / 'benchmark_results.json').write_text(
        json.dumps(payload, indent=2),
        encoding='utf-8',
    )
    return report_path
