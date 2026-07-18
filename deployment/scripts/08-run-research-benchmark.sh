#!/usr/bin/env bash
# Run research benchmark: ML + OR comparative tables for paper.
# Usage: bash scripts/08-run-research-benchmark.sh

set -e
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
AI_DIR="$ROOT/backend"
OUT="$AI_DIR/data/research"

cd "$AI_DIR"
[ -d .venv ] || python3 -m venv .venv
source .venv/bin/activate
pip install -q -r requirements.txt

echo "=== PAM AI Research Benchmark (ML + OR) ==="
python -m aiss.evaluation.run_benchmark --output "$OUT"

echo ""
echo "Results written to:"
echo "  $OUT/BENCHMARK_REPORT.md"
echo "  $OUT/benchmark_results.json"
echo ""
head -40 "$OUT/BENCHMARK_REPORT.md"
