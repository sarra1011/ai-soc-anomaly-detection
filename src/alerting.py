"""Alert channels and (safe) IP blocking for the live detector.

Notifier : console + JSONL file always; Telegram and e-mail when configured through environment variables:
    TELEGRAM_BOT_TOKEN, TELEGRAM_CHAT_ID
    SMTP_HOST, SMTP_PORT (587), SMTP_USER, SMTP_PASSWORD, ALERT_TO
Blocker  : DRY-RUN by default (prints the firewall command). Real blocking needs --enforce, and it refuses to touch
           private, loopback or allow-listed addresses, so you cannot lock yourself out.
"""
import ipaddress
import json
import os
import smtplib
import subprocess
import urllib.parse
import urllib.request
from email.message import EmailMessage
from pathlib import Path

ICON = {"CRITICAL": "[!!!]", "HIGH": "[!!]", "REVIEW": "[?]"}
RANK = {"CRITICAL": 3, "HIGH": 2, "REVIEW": 1}


def format_alert(inc):
    lines = [f"{ICON.get(inc['severity'], '')} {inc['severity']} incident - source {inc['source']}",
             f"time   : {inc['start']} -> {inc['end']}  ({inc['windows']} windows, {inc['sources']} source(s))"]
    for r in inc["rules"]:
        lines.append(f"rule   : {r['id']} - {r['desc']}")
    if not inc["rules"]:
        lines.append("rule   : none matched - ML anomaly score only (review manually)")
    if inc.get("action"):
        lines.append(f"action : {inc['action']}")
    return "\n".join(lines)


class Notifier:
    def __init__(self, jsonl_path="reports/live_alerts.jsonl", min_notify="HIGH"):
        self.jsonl = Path(jsonl_path)
        self.jsonl.parent.mkdir(parents=True, exist_ok=True)
        self.min_notify = min_notify
        self.tg_token = os.getenv("TELEGRAM_BOT_TOKEN")
        self.tg_chat = os.getenv("TELEGRAM_CHAT_ID")
        self.smtp_host = os.getenv("SMTP_HOST")
        self.channels = ["console", "file"] + (["telegram"] if self.tg_token and self.tg_chat else []) \
            + (["email"] if self.smtp_host and os.getenv("ALERT_TO") else [])

    def send(self, inc):
        text = format_alert(inc)
        print(text + "\n", flush=True)
        with open(self.jsonl, "a") as f:
            f.write(json.dumps(inc, default=str) + "\n")
        if RANK[inc["severity"]] < RANK[self.min_notify]:
            return
        if "telegram" in self.channels:
            self._telegram(text)
        if "email" in self.channels:
            self._email(f"[SOC] {inc['severity']} incident from {inc['source']}", text)

    def _telegram(self, text):
        try:
            data = urllib.parse.urlencode({"chat_id": self.tg_chat, "text": text}).encode()
            urllib.request.urlopen(f"https://api.telegram.org/bot{self.tg_token}/sendMessage", data, timeout=10).read()
        except Exception as e:
            print(f"(telegram failed: {e})")

    def _email(self, subject, text):
        try:
            m = EmailMessage()
            m["Subject"], m["From"], m["To"] = subject, os.getenv("SMTP_USER", "soc@localhost"), os.environ["ALERT_TO"]
            m.set_content(text)
            with smtplib.SMTP(self.smtp_host, int(os.getenv("SMTP_PORT", "587")), timeout=15) as s:
                s.starttls()
                if os.getenv("SMTP_USER"):
                    s.login(os.environ["SMTP_USER"], os.environ.get("SMTP_PASSWORD", ""))
                s.send_message(m)
        except Exception as e:
            print(f"(email failed: {e})")


class Blocker:
    def __init__(self, enforce=False, allowlist=()):
        self.enforce = enforce
        self.allow = set(allowlist)
        self.blocked = set()

    def refusal(self, ip):
        try:
            a = ipaddress.ip_address(ip)
        except ValueError:
            return "not an IP address"
        if ip in self.allow:
            return "allow-listed"
        if a.is_private or a.is_loopback or a.is_link_local or a.is_reserved or a.is_multicast:
            return "private/loopback address (never blocked)"
        return None

    def block(self, ip):
        """Returns a human-readable description of what was (or would be) done."""
        why = self.refusal(ip)
        if why:
            return f"NOT blocking {ip}: {why}"
        if ip in self.blocked:
            return f"{ip} already blocked"
        cmd = ["sudo", "iptables", "-I", "INPUT", "-s", ip, "-j", "DROP"]
        if not self.enforce:
            return f"DRY-RUN would run: {' '.join(cmd)}"
        r = subprocess.run(cmd, capture_output=True, text=True)
        if r.returncode == 0:
            self.blocked.add(ip)
            return f"BLOCKED {ip} ({' '.join(cmd)})"
        return f"block of {ip} FAILED: {r.stderr.strip()}"
