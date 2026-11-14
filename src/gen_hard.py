#!/usr/bin/env python3
"""Step 5 - HARD dataset: stealthy attacks + legit-but-weird behaviour (to test the pipeline honestly).

Attacks (label 1):  slow_low (1 fail / ~5 min for hours), distributed_bf (many IPs, 3 fails each)
Benign (label 0):   admin_night (internal admin at 23h with sudo), typo_burst (user fat-fingers 12x then succeeds),
                    vpn_day (external IP, daytime, publickey)
Plus the usual normal traffic and the original easy attacks.
Output: data/hard/auth.log, data/hard/labels.csv
"""
import argparse
import csv
import random
import sys
from datetime import datetime, timedelta
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import gen_logs as g  # noqa: E402


def slow_low(t):
    ip = random.choice(g.ATTACKER_IPS)
    out = []
    for _ in range(random.randint(50, 80)):
        t += timedelta(minutes=random.uniform(3, 7))
        pid = random.randint(1000, 30000)
        out.append((t, g.line(t, "sshd", pid, f"Failed password for root from {ip} port {random.randint(30000, 60000)} ssh2"), 1, "slow_low"))
    return out


def distributed_bf(t):
    out = []
    for _ in range(random.randint(15, 25)):
        ip = ".".join(str(random.randint(11, 223)) for _ in range(4))
        tt = t + timedelta(seconds=random.randint(0, 1500))
        for _ in range(3):
            tt += timedelta(seconds=random.randint(2, 20))
            u = random.choice(["root", "admin"])
            pid = random.randint(1000, 30000)
            out.append((tt, g.line(tt, "sshd", pid, f"Failed password for {u} from {ip} port {random.randint(30000, 60000)} ssh2"), 1, "distributed_bf"))
    return out


def admin_night(t):
    t = t.replace(hour=23, minute=random.randint(0, 40))
    ip = random.choice(g.INTERNAL_IPS)
    out = g.normal_session(t, "sarra", ip)
    pid = random.randint(1000, 30000)
    t2 = t + timedelta(seconds=90)
    out.append((t2, g.line(t2, "sudo", pid, "sarra : TTY=pts/0 ; PWD=/home/sarra ; USER=root ; COMMAND=/usr/bin/apt upgrade"), 0, "admin_night"))
    return [(a, b, 0, "admin_night") for a, b, _, _ in out]


def typo_burst(t):
    user, ip = random.choice(g.USERS), random.choice(g.INTERNAL_IPS)
    out = []
    for _ in range(random.randint(10, 14)):
        t += timedelta(seconds=random.randint(1, 4))
        pid = random.randint(1000, 30000)
        out.append((t, g.line(t, "sshd", pid, f"Failed password for {user} from {ip} port {random.randint(30000, 60000)} ssh2"), 0, "typo_burst"))
    t += timedelta(seconds=5)
    out.append((t, g.line(t, "sshd", pid, f"Accepted password for {user} from {ip} port 40111 ssh2"), 0, "typo_burst"))
    return out


def vpn_day(t):
    ip = f"41.62.{random.randint(1, 250)}.{random.randint(1, 250)}"
    t = t.replace(hour=random.randint(9, 17))
    return [(a, b, 0, "vpn_day") for a, b, _, _ in g.normal_session(t, random.choice(g.USERS), ip)]


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--days", type=int, default=7)
    ap.add_argument("--seed", type=int, default=7)
    ap.add_argument("--out", default="data/hard")
    a = ap.parse_args()
    random.seed(a.seed)

    start = datetime.now().replace(hour=0, minute=0, second=0, microsecond=0) - timedelta(days=a.days)
    ev = []
    for d in range(a.days):
        day = start + timedelta(days=d)
        at = lambda h0, h1: day + timedelta(hours=random.randint(h0, h1), minutes=random.randint(0, 59))  # noqa: E731
        for _ in range(random.randint(40, 70)):
            ev += g.normal_session(at(8, 18), random.choice(g.USERS), random.choice(g.INTERNAL_IPS))
        for _ in range(random.randint(3, 8)):
            ev += g.typo_fail(at(8, 18), random.choice(g.USERS), random.choice(g.INTERNAL_IPS))
        for fn in random.sample([g.brute_force, g.brute_force_success, g.offhours_login, g.priv_esc], k=1):
            ev += fn(at(0, 23))
        ev += random.choice([slow_low, distributed_bf])(at(0, 16))          # hard attack every day
        ev += admin_night(day)                                              # benign weirdness every day
        ev += typo_burst(at(8, 18))
        for _ in range(random.randint(1, 3)):
            ev += vpn_day(day)

    ev.sort(key=lambda e: e[0])
    out = Path(a.out)
    out.mkdir(parents=True, exist_ok=True)
    with open(out / "auth.log", "w") as f, open(out / "labels.csv", "w", newline="") as fh:
        w = csv.writer(fh)
        w.writerow(["line_no", "label", "attack_type"])
        for i, (_, text, lab, typ) in enumerate(ev, 1):
            f.write(text + "\n")
            w.writerow([i, lab, typ])
    print(f"OK: {len(ev)} lines ({sum(e[2] for e in ev)} attack lines) -> {out}/auth.log")


if __name__ == "__main__":
    main()
