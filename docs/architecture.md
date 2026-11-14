# SOC System Architecture

```
 auth.log (real or synthetic)
        │
        ▼
 ┌────────────────┐   ┌─────────────────────┐   ┌───────────────────┐
 │ 1. Parsing     │ → │ 2. Feature          │ → │ 3a. Isolation     │
 │ parse_features │   │ engineering         │   │ Forest (ML)       │
 │                │   │ 5-min windows,      │   │ detect.py         │
 │ regex → events │   │ 1h/6h rolling,      │   └─────────┬─────────┘
 └────────────────┘   │ global distinct IPs │             │ anomaly score
                      └──────────┬──────────┘             ▼
                                 │            ┌───────────────────────┐
                                 └──────────► │ 3b. Detection rules   │
                                              │ R1..R7 (MITRE mapped) │
                                              └───────────┬───────────┘
                                                          ▼
                                              ┌───────────────────────┐
                                              │ 4. Hybrid + incident  │
                                              │ grouping + severity   │
                                              │ hybrid.py             │
                                              └───────────┬───────────┘
                                                          ▼
                                              ┌───────────────────────┐
                                              │ 5. Dashboard (PNG)    │
                                              │ report.py             │
                                              └───────────────────────┘
```

## Design decisions

- **Unsupervised ML.** Attacks are ~1 % of windows, so the Isolation Forest is trained without labels. Labels are only used for evaluation.
- **Rules + ML.** Rules give precision on known attacks; the ML score surfaces unknown ones as `REVIEW` alerts.
- **Windows per entity.** An entity is a source IP (ssh lines) or a user (sudo lines). Long-window features catch slow-and-low attacks, a global feature catches distributed ones.
- **Incidents, not alerts.** Windows from the same source (or the same distributed campaign) less than 30 minutes apart are merged, which turns ~300 window alerts into ~20 incidents.
- **Honest evaluation.** A second "hard" dataset adds stealth attacks and benign look-alikes (admin working at night, user mistyping a password), generated with a seed that was never used while tuning the rules.

## Detection rules

| Rule | Detects | Severity | MITRE ATT&CK |
|---|---|---|---|
| R1 | ≥10 failed logins in 5 min from an external IP / several users | HIGH | T1110.001 |
| R2 | ≥4 distinct users tried (password spraying) | HIGH | T1110.003 |
| R3 | Failures followed by a successful login | CRITICAL | T1110, T1078 |
| R4 | Successful off-hours login from an external IP | HIGH | T1078 |
| R5 | Denied sudo, root shell or `/etc/shadow` access | HIGH | T1548.003, T1003.008 |
| R6 | Slow brute force (≥8 failures/h spread over ≥5 windows) | HIGH | T1110.001 |
| R7 | ≥8 distinct IPs failing against root/admin in 30 min | HIGH | T1110 |

## Live mode

`src/live.py` follows a log file, keeps the last 6 hours of parsed events, re-scores every 5 minutes of log time with the same rules and Isolation Forest, and raises each incident once (again only if its severity escalates). Alerts go to the console and `reports/live_alerts.jsonl`, plus Telegram and e-mail when configured. CRITICAL incidents trigger the IP blocker, which is a dry run unless `--enforce` is given and never touches private, loopback or allow-listed addresses.

## Roadmap

- [x] Real attacks against a real sshd (`lab/`), validation on the public Loghub OpenSSH logs, model comparison
- [x] Live mode with alerting and automatic IP blocking
- [ ] Wazuh integration with real logs (needs ~10 GB free disk)
- [ ] Sequence models (LSTM / transformer on event sequences)
- [ ] Live dashboard (Grafana / Streamlit)
