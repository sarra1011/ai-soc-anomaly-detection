#!/usr/bin/env python3
"""Step 1 - Synthetic Linux auth.log generator with injected attacks.

Outputs:
  data/raw/auth.log     syslog-style SSH/sudo logs (what the SOC ingests)
  data/raw/labels.csv   ground truth per line (0 normal / 1 attack + type) for evaluation only
"""
import argparse
import csv
import random
from datetime import datetime, timedelta
from pathlib import Path

HOST = "srv-ensi-01"
USERS = ["sarra", "ahmed", "mariem", "youssef", "rihab", "deploy"]
ADMINS = ["sarra", "deploy"]
INTERNAL_IPS = [f"10.0.0.{i}" for i in range(10, 40)]
ATTACKER_IPS = ["185.220.101.4", "45.155.205.233", "103.77.192.18", "91.240.118.172"]
FAKE_USERS = ["root", "admin", "test", "oracle", "postgres", "ubuntu", "git", "pi"]


def ts(t):
    return t.strftime("%b %d %H:%M:%S").replace(" 0", "  ", 1) if t.day < 10 else t.strftime("%b %d %H:%M:%S")


def line(t, proc, pid, msg):
    return f"{ts(t)} {HOST} {proc}[{pid}]: {msg}"


def normal_session(t, user, ip):
    pid = random.randint(1000, 30000)
    out = [(t, line(t, "sshd", pid, f"Accepted publickey for {user} from {ip} port {random.randint(30000, 60000)} ssh2"))]
    t2 = t + timedelta(seconds=1)
    out.append((t2, line(t2, "sshd", pid, f"pam_unix(sshd:session): session opened for user {user}")))
    if user in ADMINS and random.random() < 0.5:
        for _ in range(random.randint(1, 3)):
            t2 += timedelta(seconds=random.randint(20, 300))
            cmd = random.choice(["/usr/bin/apt update", "/bin/systemctl status nginx", "/usr/bin/journalctl -xe"])
            out.append((t2, line(t2, "sudo", pid + 1, f"{user} : TTY=pts/0 ; PWD=/home/{user} ; USER=root ; COMMAND={cmd}")))
    t3 = t2 + timedelta(seconds=random.randint(60, 3600))
    out.append((t3, line(t3, "sshd", pid, f"pam_unix(sshd:session): session closed for user {user}")))
    return [(a, b, 0, "normal") for a, b in out]


def typo_fail(t, user, ip):
    pid = random.randint(1000, 30000)
    return [(t, line(t, "sshd", pid, f"Failed password for {user} from {ip} port {random.randint(30000, 60000)} ssh2"), 0, "normal")]


def brute_force(t):
    ip = random.choice(ATTACKER_IPS)
    out = []
    for _ in range(random.randint(40, 120)):
        t += timedelta(seconds=random.uniform(0.3, 3))
        u = random.choice(FAKE_USERS)
        pid = random.randint(1000, 30000)
        inv = "invalid user " if u not in USERS and u != "root" else ""
        out.append((t, line(t, "sshd", pid, f"Failed password for {inv}{u} from {ip} port {random.randint(30000, 60000)} ssh2"), 1, "brute_force"))
    return out


def brute_force_success(t):
    out = brute_force(t)
    t = out[-1][0] + timedelta(seconds=2)
    ip = out[-1][1].split(" from ")[1].split()[0]
    pid = random.randint(1000, 30000)
    out.append((t, line(t, "sshd", pid, f"Accepted password for deploy from {ip} port 44122 ssh2"), 1, "brute_force_success"))
    t += timedelta(seconds=5)
    out.append((t, line(t, "sudo", pid + 1, "deploy : TTY=pts/1 ; PWD=/tmp ; USER=root ; COMMAND=/bin/bash"), 1, "priv_esc"))
    return out


def offhours_login(t):
    user, ip = random.choice(USERS), random.choice(ATTACKER_IPS)
    t = t.replace(hour=random.randint(1, 4))
    pid = random.randint(1000, 30000)
    return [(t, line(t, "sshd", pid, f"Accepted password for {user} from {ip} port {random.randint(30000, 60000)} ssh2"), 1, "offhours_foreign_login")]


def priv_esc(t):
    user = random.choice([u for u in USERS if u not in ADMINS])
    pid = random.randint(1000, 30000)
    out = []
    for _ in range(random.randint(3, 6)):
        t += timedelta(seconds=random.randint(2, 20))
        out.append((t, line(t, "sudo", pid, f"{user} : user NOT in sudoers ; TTY=pts/0 ; PWD=/home/{user} ; USER=root ; COMMAND=/bin/cat /etc/shadow"), 1, "priv_esc"))
    return out


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--days", type=int, default=7)
    ap.add_argument("--seed", type=int, default=42)
    ap.add_argument("--out", default="data/raw")
    a = ap.parse_args()
    random.seed(a.seed)

    start = datetime.now().replace(hour=0, minute=0, second=0, microsecond=0) - timedelta(days=a.days)
    events = []
    for d in range(a.days):
        day = start + timedelta(days=d)
        # normal activity: working hours 08-19
        for _ in range(random.randint(40, 70)):
            t = day + timedelta(hours=random.randint(8, 18), minutes=random.randint(0, 59), seconds=random.randint(0, 59))
            u = random.choice(USERS)
            events += normal_session(t, u, random.choice(INTERNAL_IPS))
        for _ in range(random.randint(3, 8)):
            t = day + timedelta(hours=random.randint(8, 18), minutes=random.randint(0, 59))
            events += typo_fail(t, random.choice(USERS), random.choice(INTERNAL_IPS))
        # attacks: ~1-2 per day
        for fn in random.sample([brute_force, brute_force_success, offhours_login, priv_esc], k=random.randint(1, 2)):
            t = day + timedelta(hours=random.randint(0, 23), minutes=random.randint(0, 59))
            events += fn(t)

    events.sort(key=lambda e: e[0])
    out = Path(a.out)
    out.mkdir(parents=True, exist_ok=True)
    with open(out / "auth.log", "w") as f, open(out / "labels.csv", "w", newline="") as g:
        w = csv.writer(g)
        w.writerow(["line_no", "label", "attack_type"])
        for i, (_, text, lab, typ) in enumerate(events, 1):
            f.write(text + "\n")
            w.writerow([i, lab, typ])
    n_att = sum(e[2] for e in events)
    print(f"OK: {len(events)} lines ({n_att} attack lines) -> {out}/auth.log")


if __name__ == "__main__":
    main()
