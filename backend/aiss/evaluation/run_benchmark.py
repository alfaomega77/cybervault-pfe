"""CLI entrypoint for research benchmarks."""

import argparse
from pathlib import Path

from .benchmark import run_full_benchmark


def main():
    parser = argparse.ArgumentParser(description='Run PAM AI/ML/OR benchmark')
    parser.add_argument('--output', default='data/research', help='Output directory')
    parser.add_argument('--seed', type=int, default=42)
    args = parser.parse_args()
    report = run_full_benchmark(args.output, seed=args.seed)
    print(f'Benchmark complete: {report}')


if __name__ == '__main__':
    main()
