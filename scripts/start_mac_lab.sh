#!/usr/bin/env bash
set -e
cd "$(dirname "$0")/.."
echo "========================================================"
echo "  ADONAI — Personal Cyber-Intelligence & 3D Lab Host"
echo "========================================================"
python3 scripts/discover_environment.py
echo "[ADONAI] Starting Mac Intelligence Backend & 3D Dashboard on http://127.0.0.1:8410 ..."
echo "[ADONAI] Android Companion Simulator available at http://127.0.0.1:8410/mobile"
exec python3 -m uvicorn backend.main:app --host 127.0.0.1 --port 8410
