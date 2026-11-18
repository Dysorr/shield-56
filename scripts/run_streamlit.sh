#!/usr/bin/env bash
# Resolve paths independently of the managed workflow's working directory.
set -euo pipefail
cd "$(dirname "${BASH_SOURCE[0]}")/.."
exec python -m streamlit run app.py \
  --server.address 0.0.0.0 \
  --server.port "${PORT:-21819}" \
  --server.headless true \
  --server.fileWatcherType none \
  --browser.gatherUsageStats false
