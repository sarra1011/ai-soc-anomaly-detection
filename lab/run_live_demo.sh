#!/usr/bin/env bash
# Live demo: real sshd + real attacks, with the live detector printing alerts AS the attacks happen.
#   bash lab/run_live_demo.sh            (dry-run IP blocking; add ENFORCE=1 to really block public IPs - loopback is never blocked)
set -euo pipefail
cd "$(dirname "$0")/.."
[ -d .venv ] && source .venv/bin/activate
pip install -q paramiko
[ -f models/iforest.joblib ] || { python3 src/gen_logs.py > /dev/null && python3 src/parse_features.py > /dev/null && python3 src/detect.py > /dev/null; }
bash lab/lab_up.sh
trap 'kill ${LIVE:-0} 2>/dev/null || true; bash lab/lab_down.sh' EXIT
YEAR=$(date +%Y)
EXTRA=""; [ "${ENFORCE:-0}" = "1" ] && EXTRA="--enforce"
python3 -u src/live.py --log lab_data/auth.log --follow --year "$YEAR" $EXTRA &
LIVE=$!
python3 lab/simulate.py
sleep 8
echo "--- live alerts saved in reports/live_alerts.jsonl"
