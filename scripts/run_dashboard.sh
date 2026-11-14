#!/usr/bin/env bash
# Live SOC dashboard on http://localhost:8501  (reads reports/live_alerts.jsonl and reports/*_incidents.csv)
set -euo pipefail
cd "$(dirname "$0")/.."
[ -d .venv ] && source .venv/bin/activate
python3 -c "import streamlit" 2>/dev/null || pip install -q -r requirements-dashboard.txt
exec streamlit run src/dashboard.py --server.headless true --browser.gatherUsageStats false "$@"
