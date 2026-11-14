#!/usr/bin/env bash
# Step 8a - Deploy a single-node Wazuh (manager + indexer + dashboard) with Docker.
# Needs ~4 GB free RAM and ~3 GB of downloads. Run:  bash setup_wazuh.sh
set -euo pipefail

VERSION="v4.14.10"
DIR="$HOME/wazuh-docker"

# docker with or without sudo
if docker ps >/dev/null 2>&1; then D="docker"; else D="sudo docker"; fi
echo "[1/6] using: $D"

echo "[2/6] checking ports"
for p in 443 1514 1515 55000 9200; do
  if ss -ltn "( sport = :$p )" | grep -q LISTEN; then echo "  !! port $p already in use - free it first"; exit 1; fi
done

echo "[3/6] kernel setting for the indexer (needs sudo)"
sudo sysctl -w vm.max_map_count=262144
echo "vm.max_map_count=262144" | sudo tee /etc/sysctl.d/99-wazuh.conf >/dev/null

echo "[4/6] getting wazuh-docker $VERSION"
[ -d "$DIR" ] || git clone -q --depth 1 --branch "$VERSION" https://github.com/wazuh/wazuh-docker.git "$DIR"
cd "$DIR/single-node"

echo "[5/6] generating certificates + starting containers (first pull takes a few minutes)"
$D compose -f generate-indexer-certs.yml run --rm generator
$D compose up -d

echo "[6/6] waiting for the dashboard (up to 5 min)"
for i in $(seq 1 60); do
  code=$(curl -sk -o /dev/null -w "%{http_code}" https://localhost || true)
  if [ "$code" = "200" ] || [ "$code" = "302" ]; then break; fi
  sleep 5
done

$D compose ps
echo
echo "READY (HTTP $code)"
echo "Dashboard : https://localhost   (accept the self-signed certificate warning)"
echo "Login     : admin / SecretPassword"
echo "Stop      : cd $DIR/single-node && $D compose down"
