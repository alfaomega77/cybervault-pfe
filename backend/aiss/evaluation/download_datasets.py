"""Download public CERT + LANL samples used by CyberVault benchmarks.

CERT r4.2 logon.csv  → HuggingFace mirror (jinmang2/cert_insider_threat)
LANL cyber1          → csr.lanl.gov data-fence token API
                       (redteam full + auth head sample; full auth is ~7GB)

Usage:
  cd ai-security-service
  python -m aiss.evaluation.download_datasets
  python -m aiss.evaluation.download_datasets --auth-lines 200000
"""

from __future__ import annotations

import argparse
import csv
import gzip
import json
import urllib.parse
import urllib.request
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
DATA = ROOT / 'data' / 'datasets'
CERT_HF_LOGON = (
    'https://huggingface.co/datasets/jinmang2/cert_insider_threat/'
    'resolve/main/r4.2/logon.csv'
)
CERT_HF_INSIDERS = (
    'https://huggingface.co/datasets/jinmang2/cert_insider_threat/'
    'resolve/main/answers/insiders.csv'
)


def _download(url: str, dest: Path, timeout: int = 600) -> None:
    dest.parent.mkdir(parents=True, exist_ok=True)
    print(f'Downloading {url}\n  → {dest}')
    req = urllib.request.Request(url, headers={'User-Agent': 'Mozilla/5.0 CyberVault/1.0'})
    with urllib.request.urlopen(req, timeout=timeout) as resp, dest.open('wb') as out:
        while True:
            chunk = resp.read(1024 * 1024)
            if not chunk:
                break
            out.write(chunk)
    print(f'  ok ({dest.stat().st_size / 1e6:.1f} MB)')


def _lanl_token(email: str, usage: str) -> str:
    qs = urllib.parse.urlencode({'email': email, 'usage': usage})
    url = f'https://csr.lanl.gov/data-fence/token?{qs}'
    req = urllib.request.Request(url, headers={'User-Agent': 'Mozilla/5.0'})
    with urllib.request.urlopen(req, timeout=60) as resp:
        return resp.read().decode('utf-8').strip()


def download_cert() -> None:
    cert = DATA / 'cert'
    _download(CERT_HF_LOGON, cert / 'logon.csv')
    answers = DATA / 'downloads' / 'answers'
    _download(CERT_HF_INSIDERS, answers / 'insiders.csv')
    users = set()
    with (answers / 'insiders.csv').open(newline='', encoding='utf-8') as fp:
        for row in csv.DictReader(fp):
            if str(row.get('dataset', '')).startswith('4.2'):
                users.add(row['user'].strip())
    (cert / 'answers.json').write_text(
        json.dumps(
            {
                'malicious_users': sorted(users),
                'dataset': 'CERT r4.2',
                'source': 'huggingface jinmang2/cert_insider_threat',
            },
            indent=2,
        ),
        encoding='utf-8',
    )
    print(f'CERT ready: {len(users)} malicious users in answers.json')


def download_lanl(email: str, usage: str, auth_lines: int) -> None:
    lanl = DATA / 'lanl'
    lanl.mkdir(parents=True, exist_ok=True)
    token = _lanl_token(email, usage)
    base = f'https://csr.lanl.gov/data-fence/{token}/cyber1'

    # redteam (tiny)
    redteam_gz = DATA / 'downloads' / 'redteam.txt.gz'
    _download(f'{base}/redteam.txt.gz', redteam_gz, timeout=120)
    raw = gzip.decompress(redteam_gz.read_bytes()).decode('utf-8', errors='replace')
    (lanl / 'redteam_raw.txt').write_text(raw, encoding='utf-8')
    users = set()
    for line in raw.splitlines():
        parts = line.split(',')
        if len(parts) >= 2:
            users.add(parts[1].split('@')[0])
    (lanl / 'redteam.txt').write_text('\n'.join(sorted(users)) + '\n', encoding='utf-8')
    print(f'LANL redteam users: {len(users)}')

    # auth sample (stream first N lines — full file is ~7GB)
    token = _lanl_token(email, usage)
    url = f'https://csr.lanl.gov/data-fence/{token}/cyber1/auth.txt.gz'
    print(f'Streaming first {auth_lines} auth lines…')
    req = urllib.request.Request(url, headers={'User-Agent': 'Mozilla/5.0'})
    out_path = lanl / 'auth.txt'
    n = 0
    with urllib.request.urlopen(req, timeout=300) as resp:
        with gzip.GzipFile(fileobj=resp) as gz, out_path.open('w', encoding='utf-8') as out:
            for line in gz:
                out.write(line.decode('utf-8', errors='replace'))
                n += 1
                if n >= auth_lines:
                    break
                if n % 50000 == 0:
                    print(f'  … {n} lines')
    print(f'LANL auth sample ready: {n} lines → {out_path}')


def main():
    parser = argparse.ArgumentParser(description='Download CERT + LANL for CyberVault')
    parser.add_argument('--skip-cert', action='store_true')
    parser.add_argument('--skip-lanl', action='store_true')
    parser.add_argument('--auth-lines', type=int, default=150_000)
    parser.add_argument('--email', default='cybervault.research@example.com')
    parser.add_argument(
        '--usage',
        default='Academic research on privileged-access anomaly detection (CyberVault / JumpServer)',
    )
    args = parser.parse_args()
    DATA.mkdir(parents=True, exist_ok=True)
    if not args.skip_cert:
        download_cert()
    if not args.skip_lanl:
        download_lanl(args.email, args.usage, args.auth_lines)
    print('\nDone. Point the notebook to DATASET_SOURCE = cert | lanl')


if __name__ == '__main__':
    main()
