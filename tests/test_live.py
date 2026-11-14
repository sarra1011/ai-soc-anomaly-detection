import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "src"))
import alerting  # noqa: E402
import live  # noqa: E402


class Collect:
    def __init__(self):
        self.sent = []

    def send(self, inc):
        self.sent.append(inc)


def test_blocker_never_touches_private_or_allowlisted():
    b = alerting.Blocker(enforce=True, allowlist=["8.8.8.8"])
    for ip in ("127.0.0.2", "10.0.0.5", "192.168.1.9", "172.16.3.4", "8.8.8.8", "not-an-ip"):
        assert b.block(ip).startswith("NOT blocking")


def test_blocker_dry_run_does_not_execute(monkeypatch):
    called = []
    monkeypatch.setattr(alerting.subprocess, "run", lambda *a, **k: called.append(a))
    out = alerting.Blocker(enforce=False).block("185.220.101.4")
    assert out.startswith("DRY-RUN") and "iptables" in out and not called


def test_blocker_enforce_runs_iptables(monkeypatch):
    class R:
        returncode, stderr = 0, ""
    cmds = []
    monkeypatch.setattr(alerting.subprocess, "run", lambda c, **k: cmds.append(c) or R())
    b = alerting.Blocker(enforce=True)
    assert b.block("185.220.101.4").startswith("BLOCKED")
    assert cmds[0][:5] == ["sudo", "iptables", "-I", "INPUT", "-s"]
    assert b.block("185.220.101.4").endswith("already blocked")


def test_notifier_writes_jsonl_and_respects_threshold(tmp_path, monkeypatch):
    monkeypatch.delenv("TELEGRAM_BOT_TOKEN", raising=False)
    n = alerting.Notifier(jsonl_path=tmp_path / "a.jsonl")
    n.send(dict(severity="REVIEW", source="1.2.3.4", start="s", end="e", windows=1, sources=1, rules=[]))
    assert json.loads((tmp_path / "a.jsonl").read_text())["source"] == "1.2.3.4"


def test_live_detector_raises_critical_and_dry_run_block():
    lines = [f"Nov 13 03:05:{s:02d} srv sshd[1]: Failed password for root from 185.220.101.4 port 40000 ssh2"
             for s in range(0, 50)]
    lines.append("Nov 13 03:06:10 srv sshd[1]: Accepted password for deploy from 185.220.101.4 port 40001 ssh2")
    lines.append("Nov 13 03:30:00 srv sshd[1]: Accepted publickey for ahmed from 10.0.0.5 port 30000 ssh2")  # closes the window
    sink = Collect()
    det = live.LiveDetector(None, sink, alerting.Blocker(enforce=False), 2026)
    for ln in lines:
        det.feed(ln)
    det.finish()
    crit = [i for i in sink.sent if i["severity"] == "CRITICAL"]
    assert crit and crit[0]["source"] == "185.220.101.4"
    assert crit[0]["action"].startswith("DRY-RUN")


def test_same_incident_is_not_reported_twice():
    lines = [f"Nov 13 03:05:{s:02d} srv sshd[1]: Failed password for root from 185.220.101.4 port 40000 ssh2"
             for s in range(0, 50)]
    lines.append("Nov 13 03:40:00 srv sshd[1]: Accepted publickey for ahmed from 10.0.0.5 port 30000 ssh2")
    sink = Collect()
    det = live.LiveDetector(None, sink, alerting.Blocker(), 2026)
    for ln in lines:
        det.feed(ln)
    det.evaluate()
    det.evaluate()
    assert len([i for i in sink.sent if i["source"] == "185.220.101.4"]) == 1
