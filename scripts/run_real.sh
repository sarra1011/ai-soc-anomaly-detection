#!/usr/bin/env bash
# Run the detector on REAL public SSH logs (Loghub OpenSSH, 2k-line sample; Dec 2015, real internet attackers).
#   bash scripts/run_real.sh          # 2k sample (fast)
#   FULL=1 bash scripts/run_real.sh   # full 655k-line dataset from Zenodo (~70 MB download)
set -euo pipefail
cd "$(dirname "$0")/.."
[ -d .venv ] && source .venv/bin/activate
mkdir -p data/real reports
if [ "${FULL:-0}" = "1" ]; then
  LOG=data/real/SSH.log
  if [ ! -f "$LOG" ]; then
    curl -fL -o data/real/SSH.tar.gz "https://zenodo.org/records/8196385/files/SSH.tar.gz?download=1"
    tar xzf data/real/SSH.tar.gz -C data/real
  fi
else
  LOG=data/real/OpenSSH_2k.log
  [ -f "$LOG" ] || curl -fsSL -o "$LOG" https://raw.githubusercontent.com/logpai/loghub/master/OpenSSH/OpenSSH_2k.log
fi
python3 src/parse_features.py --log "$LOG" --labels none --out data/real_processed --year 2015 > /dev/null
python3 src/hybrid.py --features data/real_processed/features.csv --report reports/real_alerts.csv
python3 src/report.py --events data/real_processed/events.csv --incidents reports/real_alerts_incidents.csv --out reports/real_dashboard.png
echo "Dashboard: reports/real_dashboard.png"
