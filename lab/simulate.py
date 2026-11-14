#!/usr/bin/env python3
"""Real attacks against the lab sshd (127.0.0.1:2222) from different loopback source IPs.
Each attacker/normal client = one 127.0.0.N source address, so the logs carry real sshd lines per source and the
ground truth is exact: 127.0.0.1 = legitimate, every other address = an attack.
"""
import datetime
import json
import random
import socket
import sys
import time
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

import logging

import paramiko

logging.getLogger("paramiko").setLevel(logging.CRITICAL)   # silence harmless close-twice noise

ROOT = Path(__file__).resolve().parent.parent
D = ROOT / "lab_data"
CLOCK = json.load(open(D / "clock.json"))
BASE = datetime.datetime.fromisoformat(CLOCK["base"])
F = CLOCK["factor"]
PW = {"lab_alice": "Alice#2026", "lab_bob": "Bob#2026", "lab_deploy": "Deploy#2026"}
WORDS = ["123456", "password", "admin", "letmein", "qwerty", "toor", "welcome", "Passw0rd", "root", "changeme"]
ATTACKS = {}     # src ip -> attack type (ground truth)


def vnow():
    return BASE + datetime.timedelta(seconds=(time.time() - CLOCK["real0"]) * F)


def wait_until(h, m=0):
    target = BASE.replace(hour=h, minute=m)
    while (left := (target - vnow()).total_seconds()) > 0:
        time.sleep(min(left / F, 0.5))


def vsleep(vsec):
    time.sleep(vsec / F)


def attempt(src, user, pw):
    s = socket.socket()
    try:
        s.bind((src, 0))
        s.settimeout(8)
        s.connect(("127.0.0.1", 2222))
        t = paramiko.Transport(s)
        t.start_client(timeout=8)
        t.auth_password(user, pw)
        ok = t.is_authenticated()
        t.close()
        return ok
    except Exception:
        return False
    finally:
        s.close()


def many(src, combos, threads):
    with ThreadPoolExecutor(threads) as ex:
        return list(ex.map(lambda c: attempt(src, *c), combos))


def normal_logins():
    times = sorted(random.uniform(8 * 3600, 18 * 3600) for _ in range(45))
    for i, t in enumerate(times):
        wait_until(int(t // 3600), int(t % 3600 // 60))
        u = random.choice(list(PW))
        if i % 6 == 0:
            attempt("127.0.0.1", u, "typo!")             # honest typo
        attempt("127.0.0.1", u, PW[u])


def typo_burst():
    wait_until(10, 0)
    many("127.0.0.1", [("lab_alice", f"wrong{i}") for i in range(12)], 4)
    attempt("127.0.0.1", "lab_alice", PW["lab_alice"])


def admin_night():
    wait_until(23, 0)
    attempt("127.0.0.1", "lab_deploy", PW["lab_deploy"])


def brute_force():
    ATTACKS["127.0.0.2"] = "brute_force"
    wait_until(3, 5)
    users = ["root", "admin", "test", "oracle", "ubuntu"]
    many("127.0.0.2", [(random.choice(users), random.choice(WORDS) + str(i)) for i in range(80)], 16)


def password_spray():
    ATTACKS["127.0.0.3"] = "password_spray"
    wait_until(11, 30)
    users = ["lab_alice", "lab_bob", "lab_deploy", "root", "admin"]
    many("127.0.0.3", [(u, p) for p in ("Password1", "Welcome1", "Summer2026", "Winter2026") for u in users], 6)


def slow_low():
    ATTACKS["127.0.0.4"] = "slow_low"
    wait_until(13, 0)
    for i in range(20):
        attempt("127.0.0.4", "root", WORDS[i % len(WORDS)] + str(i))
        vsleep(240)                                       # one attempt every 4 virtual minutes


def compromise():
    ATTACKS["127.0.0.5"] = "brute_force_success"
    wait_until(2, 30)
    many("127.0.0.5", [("lab_deploy", random.choice(WORDS) + str(i)) for i in range(30)], 16)
    attempt("127.0.0.5", "lab_deploy", PW["lab_deploy"])  # the attacker finally guesses it


def offhours_login():
    ATTACKS["127.0.0.6"] = "offhours_foreign_login"
    wait_until(4, 10)
    attempt("127.0.0.6", "lab_bob", PW["lab_bob"])        # stolen credentials, 04:10


def distributed():
    wait_until(15, 0)
    def one(n):
        ip = f"127.0.0.{n}"
        ATTACKS[ip] = "distributed_bf"
        vsleep(random.uniform(0, 1500))
        for _ in range(3):
            attempt(ip, random.choice(["root", "admin"]), random.choice(WORDS))
            vsleep(20)
    with ThreadPoolExecutor(12) as ex:
        list(ex.map(one, range(10, 22)))


def build_labels():
    import csv
    import re
    rows = [("line_no", "label", "attack_type")]
    for i, line in enumerate((D / "auth.log").read_text().splitlines(), 1):
        m = re.search(r"127\.0\.0\.(\d+)", line)
        ip = f"127.0.0.{m.group(1)}" if m else None
        typ = ATTACKS.get(ip)
        rows.append((i, int(typ is not None), typ or "normal"))
    with open(D / "labels.csv", "w", newline="") as f:
        csv.writer(f).writerows(rows)
    print(f"labels.csv: {len(rows) - 1} lines, {sum(r[1] for r in rows[1:])} attack lines")


def main():
    random.seed(7)
    jobs = [normal_logins, typo_burst, admin_night, brute_force, password_spray, slow_low, compromise,
            offhours_login, distributed]
    print(f"virtual day starts {BASE:%Y-%m-%d} - running {len(jobs)} scenarios in parallel (~{24 * 3600 / F / 60:.0f} min)...", flush=True)
    with ThreadPoolExecutor(len(jobs)) as ex:
        for f in [ex.submit(j) for j in jobs]:
            f.result()
    time.sleep(2)
    json.dump(ATTACKS, open(D / "attack_map.json", "w"), indent=1)
    build_labels()


if __name__ == "__main__":
    main()
