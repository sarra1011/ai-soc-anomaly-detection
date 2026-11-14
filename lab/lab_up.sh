#!/usr/bin/env bash
# Start a REAL sshd on 127.0.0.1:2222 (loopback only) whose logs are written in syslog format with an accelerated clock.
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
D="$ROOT/lab_data"; mkdir -p "$D"
FACTOR="${FACTOR:-240}"        # 1 real second = 240 virtual seconds  (a virtual day takes 6 real minutes)

sudo -v
if [ ! -x /usr/sbin/sshd ]; then
  sudo apt-get install -y openssh-server
  sudo systemctl disable --now ssh ssh.socket 2>/dev/null || true   # we only want OUR loopback instance
fi
sudo mkdir -p /run/sshd

declare -A PW=( [lab_alice]='Alice#2026' [lab_bob]='Bob#2026' [lab_deploy]='Deploy#2026' )
for u in "${!PW[@]}"; do
  id "$u" >/dev/null 2>&1 || sudo useradd -m -s /usr/sbin/nologin "$u"
  echo "$u:${PW[$u]}" | sudo chpasswd
done

[ -f "$D/hostkey" ] || sudo ssh-keygen -q -t ed25519 -N '' -f "$D/hostkey"
cat > "$D/sshd_config" <<EOF
Port 2222
ListenAddress 127.0.0.1
HostKey $D/hostkey
PasswordAuthentication yes
PubkeyAuthentication no
UsePAM no
PermitRootLogin yes
MaxStartups 500
LoginGraceTime 10
LogLevel INFO
PidFile $D/sshd.pid
EOF
sudo /usr/sbin/sshd -t -f "$D/sshd_config"

python3 - "$D" "$FACTOR" <<'PY'
import datetime, json, sys, time
d, f = sys.argv[1], float(sys.argv[2])
base = (datetime.datetime.now() - datetime.timedelta(days=1)).replace(hour=0, minute=0, second=0, microsecond=0)
json.dump({"base": base.isoformat(), "factor": f, "real0": time.time()}, open(d + "/clock.json", "w"))
PY
: > "$D/auth.log"
sudo /usr/sbin/sshd -D -e -f "$D/sshd_config" 2> >(python3 -u "$ROOT/lab/stamp.py" "$D/clock.json" "$D/auth.log") > /dev/null &
disown
sleep 2
(exec 3<>/dev/tcp/127.0.0.1/2222) 2>/dev/null && echo "sshd up on 127.0.0.1:2222 (virtual clock x$FACTOR)" || { echo "sshd failed to start"; exit 1; }
