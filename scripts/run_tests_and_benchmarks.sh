#!/usr/bin/env bash
set -e
cd "$(dirname "$0")/.."
echo "========================================================"
echo "  ADONAI — Automated Verification & Benchmark Suite"
echo "========================================================"
python3 scripts/discover_environment.py
python3 -m unittest discover -s tests -v
