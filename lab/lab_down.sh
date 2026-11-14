#!/usr/bin/env bash
# Stop the lab sshd. Add --clean to also delete the 3 lab users.
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
D="$ROOT/lab_data"
[ -f "$D/sshd.pid" ] && sudo kill "$(cat "$D/sshd.pid")" 2>/dev/null || sudo pkill -f "sshd -D -e -f $D/sshd_config" || true
if [ "${1:-}" = "--clean" ]; then
  for u in lab_alice lab_bob lab_deploy; do id "$u" >/dev/null 2>&1 && sudo userdel -r "$u" 2>/dev/null || true; done
  echo "lab users removed"
fi
echo "lab sshd stopped"
