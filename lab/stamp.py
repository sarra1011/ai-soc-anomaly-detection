#!/usr/bin/env python3
"""Reads sshd stderr lines on stdin, writes syslog-style lines (virtual accelerated clock) to a file.
usage: stamp.py clock.json out.log"""
import datetime
import json
import sys
import time

cfg = json.load(open(sys.argv[1]))
base = datetime.datetime.fromisoformat(cfg["base"])
out = open(sys.argv[2], "a", buffering=1)
for line in sys.stdin:
    v = base + datetime.timedelta(seconds=(time.time() - cfg["real0"]) * cfg["factor"])
    out.write(f"{v:%b} {v.day:2d} {v:%H:%M:%S} lab-srv sshd[4242]: {line.rstrip()}\n")
