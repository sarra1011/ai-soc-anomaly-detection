import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "src"))
import dashboard_data as dd  # noqa: E402


def _inc(sev, src, start, rules=()):
    return dict(severity=sev, source=src, start=start, end=start, windows=1, sources=1, score=0.8,
                rules=[dict(id=r, desc=f"{r} desc") for r in rules])


def _write(tmp_path, incs, tail=""):
    p = tmp_path / "live.jsonl"
    p.write_text("\n".join(json.dumps(i) for i in incs) + "\n" + tail)
    return p


def test_live_escalation_keeps_most_severe_once(tmp_path):
    p = _write(tmp_path, [_inc("REVIEW", "127.0.0.5", "2026-11-13 02:30:00"),
                          _inc("CRITICAL", "127.0.0.5", "2026-11-13 02:30:00", ["R1_bruteforce", "R3_login_after_fails"]),
                          _inc("HIGH", "127.0.0.2", "2026-11-13 03:05:00", ["R1_bruteforce"])])
    df = dd.load_live_jsonl(p)
    assert len(df) == 2
    assert df.loc[df["source"] == "127.0.0.5", "severity"].item() == "CRITICAL"
    assert dd.kpis(df) == dict(total=2, critical=1, high=1, review=0, sources=2)


def test_live_ignores_half_written_line_and_missing_file(tmp_path):
    p = _write(tmp_path, [_inc("HIGH", "1.2.3.4", "2026-11-13 03:00:00", ["R5_priv_esc"])], tail='{"severity": "HI')
    assert len(dd.load_live_jsonl(p)) == 1
    assert dd.load_live_jsonl(tmp_path / "nope.jsonl").empty
    assert dd.kpis(dd.load_live_jsonl(tmp_path / "nope.jsonl"))["total"] == 0


def test_rule_counts_and_filters(tmp_path):
    p = _write(tmp_path, [_inc("CRITICAL", "a", "2026-11-13 01:00:00", ["R1_bruteforce", "R2_password_spray"]),
                          _inc("HIGH", "b", "2026-11-13 02:00:00", ["R1_bruteforce"]),
                          _inc("REVIEW", "c", "2026-11-13 03:00:00")])
    df = dd.load_live_jsonl(p)
    rc = dd.rule_counts(df).set_index("rule")["incidents"]
    assert rc["R1_bruteforce"] == 2 and rc["R2_password_spray"] == 1
    assert list(dd.apply_filters(df, ["CRITICAL", "HIGH"], ["R2_password_spray"], "")["source"]) == ["a"]
    assert list(dd.apply_filters(df, dd.SEV_ORDER, [], "c")["source"]) == ["c"]


def test_batch_csv_loader(tmp_path):
    p = tmp_path / "x_incidents.csv"
    p.write_text("inc,severity,source,start,end,windows,sources,rules,true_attack\n"
                 "a#0,CRITICAL,1.1.1.1,2026-11-09 18:40:00,2026-11-09 18:45:00,2,1,R1_bruteforce|R3_login_after_fails,1\n"
                 "b#1,REVIEW,2.2.2.2,2026-11-09 19:00:00,2026-11-09 19:00:00,1,1,,0\n")
    df = dd.load_incidents_csv(p)
    assert df.loc[0, "rules"] == ["R1_bruteforce", "R3_login_after_fails"] and df.loc[1, "rules"] == []
