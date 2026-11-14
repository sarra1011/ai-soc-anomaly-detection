#!/usr/bin/env python3
"""Run the whole SOC pipeline end to end.

    python3 src/main.py              # easy + hard (unseen seed) datasets, dashboard
    python3 src/main.py --skip-hard  # easy dataset only (fast, used by CI)
"""
import argparse
import os
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
PY = sys.executable


def run(title, *cmd):
    print(f"\n=== {title} ===", flush=True)
    subprocess.run([PY, *cmd], cwd=ROOT, check=True, env={**os.environ, "PYTHONWARNINGS": "ignore"})


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--skip-hard", action="store_true")
    ap.add_argument("--days", type=int, default=7)
    ap.add_argument("--seed", type=int, default=42)
    a = ap.parse_args()

    for d in ("data/raw", "data/processed", "models", "reports"):
        (ROOT / d).mkdir(parents=True, exist_ok=True)

    run("1/5 Generate synthetic auth.log", "src/gen_logs.py", "--days", str(a.days), "--seed", str(a.seed))
    run("2/5 Parse logs + feature engineering", "src/parse_features.py")
    run("3/5 Train Isolation Forest", "src/detect.py")
    run("4/5 Rules + ML hybrid -> incidents (easy dataset)", "src/hybrid.py")
    if a.skip_hard:
        return
    run("Hard dataset: stealth attacks + benign look-alikes (unseen seed)", "src/gen_hard.py", "--seed", "99")
    run("Hard dataset: features", "src/parse_features.py", "--log", "data/hard/auth.log", "--labels",
        "data/hard/labels.csv", "--out", "data/hard_processed")
    run("Hard dataset: hybrid detection", "src/hybrid.py", "--features", "data/hard_processed/features.csv",
        "--report", "reports/hard_alerts.csv")
    run("Model comparison (IF vs LOF vs OC-SVM vs autoencoder vs z-score)", "src/compare_models.py")
    run("Sequence model (temporal context vs single window)", "src/sequence_model.py")
    run("5/5 Dashboard", "src/report.py")
    print("\nDone. Dashboard: reports/soc_dashboard.png")


if __name__ == "__main__":
    main()
