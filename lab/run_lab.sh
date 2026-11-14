#!/usr/bin/env bash
# One command: start real sshd -> run real attacks -> stop -> detect -> dashboard.   bash lab/run_lab.sh
set -euo pipefail
cd "$(dirname "$0")/.."
[ -d .venv ] && source .venv/bin/activate
pip install -q paramiko
bash lab/lab_up.sh
trap 'bash lab/lab_down.sh' EXIT
python3 lab/simulate.py
bash lab/lab_down.sh
trap - EXIT
YEAR=$(date +%Y)
python3 src/parse_features.py --log lab_data/auth.log --labels lab_data/labels.csv --out data/lab_processed --year "$YEAR" > /dev/null
python3 src/hybrid.py --features data/lab_processed/features.csv --report reports/lab_alerts.csv
python3 src/report.py --events data/lab_processed/events.csv --incidents reports/lab_alerts_incidents.csv --out reports/lab_dashboard.png
echo "Dashboard: reports/lab_dashboard.png   (remove lab users: bash lab/lab_down.sh --clean)"
