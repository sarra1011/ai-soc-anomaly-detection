import sys
from pathlib import Path

import pandas as pd

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "src"))
import hybrid  # noqa: E402
import parse_features as pf  # noqa: E402

LOG = """Nov  6 08:05:13 srv sshd[1]: Accepted publickey for ahmed from 10.0.0.26 port 30869 ssh2
Nov  6 08:06:00 srv sshd[2]: Failed password for invalid user oracle from 185.220.101.4 port 53172 ssh2
Nov  6 08:07:00 srv sudo[3]: deploy : TTY=pts/1 ; PWD=/tmp ; USER=root ; COMMAND=/bin/bash
Nov  6 08:08:00 srv sudo[4]: rihab : user NOT in sudoers ; TTY=pts/0 ; PWD=/ ; USER=root ; COMMAND=/bin/cat /etc/shadow
"""


def _features(rows):
    base = dict(n_events=1, n_fail=0, n_accept=0, n_sudo=0, n_sudo_denied=0, n_distinct_users=1, n_invalid_user=0,
                external=0, offhours=0, root_shell=0, fails_1h=0, fails_6h=0, active_win_1h=0, global_ips_30m=0)
    return pd.DataFrame([{**base, **r} for r in rows])


def test_parser_extracts_events(tmp_path):
    p = tmp_path / "auth.log"
    p.write_text(LOG)
    ev = pf.parse(p, 2026)
    assert list(ev["event"]) == ["ssh_accept", "ssh_fail", "sudo_cmd", "sudo_denied"]
    assert ev.loc[1, "invalid"] == 1 and ev.loc[1, "ip"] == "185.220.101.4"


def test_external_bruteforce_is_flagged():
    d = _features([dict(n_fail=40, external=1, n_distinct_users=6)])
    assert hybrid.RULES["R1_bruteforce"][0](d).iloc[0]


def test_internal_typo_burst_is_not_flagged():
    d = _features([dict(n_fail=12, n_accept=1, external=0, n_distinct_users=1)])
    assert not hybrid.RULES["R1_bruteforce"][0](d).iloc[0]
    assert not hybrid.RULES["R3_login_after_fails"][0](d).iloc[0]


def test_compromise_after_failures_is_critical():
    d = _features([dict(n_fail=30, n_accept=1, external=1)])
    assert hybrid.RULES["R3_login_after_fails"][0](d).iloc[0]
    assert hybrid.RULES["R3_login_after_fails"][1] == "CRITICAL"


def test_slow_and_low_and_distributed():
    d = _features([dict(n_fail=1, external=1, fails_1h=12, active_win_1h=9, global_ips_30m=14)])
    assert hybrid.RULES["R6_slow_bruteforce"][0](d).iloc[0]
    assert hybrid.RULES["R7_distributed_bf"][0](d).iloc[0]


def test_privilege_escalation():
    d = _features([dict(n_sudo_denied=1), dict(root_shell=1), dict()])
    assert list(hybrid.RULES["R5_priv_esc"][0](d)) == [True, True, False]


def test_unparsed_lines_get_attributed_to_their_ip(tmp_path):
    p = tmp_path / "auth.log"
    p.write_text("Nov 13 03:05:00 lab-srv sshd[1]: Invalid user nouser from 127.0.0.2 port 46053\n"
                 "Nov 13 03:05:01 lab-srv sshd[1]: Connection closed by authenticating user root 127.0.0.2 port 45275 [preauth]\n")
    ev = pf.parse(p, 2026)
    assert list(ev["ip"]) == ["127.0.0.2", "127.0.0.2"]


def test_loopback_client_is_internal_other_loopback_is_external():
    ev = pd.DataFrame({"ip": ["127.0.0.1", "127.0.0.2", "10.0.0.5", "185.220.101.4"]})
    assert list((~ev["ip"].str.match(pf.INTERNAL)).astype(int)) == [0, 1, 0, 1]


def test_sequence_windows_use_same_entity_history():
    import pandas as pd
    from sequence_model import build_sequences
    df = pd.DataFrame({
        "entity": ["a", "a", "b"],
        "win": ["2026-01-01 10:00", "2026-01-01 10:10", "2026-01-01 10:10"],
        "n_events": [3, 5, 7], "n_fail": [3, 5, 7], "n_accept": 0, "n_sudo": 0, "n_distinct_users": 1,
        "n_invalid_user": 0, "external": 1, "offhours": 0,
    })
    X, _ = build_sequences(df, length=3)
    assert X.shape == (3, 3 * 8)
    # slots are oldest..current = 10:00, 10:05, 10:10. Entity a at 10:10 sees its own 10:00 window,
    # the silent 10:05 slot is zero, and entity b (no 10:00 activity) never sees a's history.
    ev = lambda row, t: X[row][t * 8]                      # n_events column of slot t
    assert ev(1, 0) > 0 and ev(1, 1) == 0 and ev(1, 2) > 0
    assert ev(2, 0) == 0 and ev(2, 2) > 0
