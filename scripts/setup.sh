#!/usr/bin/env bash
# Create the virtualenv and install dependencies (run from anywhere).
set -euo pipefail
cd "$(dirname "$0")/.."
python3 -m venv .venv
source .venv/bin/activate
pip install --upgrade pip
pip install -r requirements.txt
echo "READY. Next: source .venv/bin/activate && python3 src/main.py"
