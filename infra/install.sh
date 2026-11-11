#!/usr/bin/env bash
# One-shot installer for the honeypot droplet (Ubuntu 24.04).
# Prerequisites (see docs/01-deployment-guide.md):
#   - real SSH already moved to port 22222 and tested
#   - repo cloned to /opt/honeypot and .env filled in
# Usage:  sudo bash /opt/honeypot/infra/install.sh
set -euo pipefail
cd /opt/honeypot

[[ $EUID -eq 0 ]] || { echo "Run with sudo"; exit 1; }
if ss -ltnp | grep -E ':22\s' | grep -q sshd; then
  echo "ERROR: the real sshd still listens on port 22. Do step 4 of the guide first."; exit 1
fi
[[ -f .env ]] || { echo "ERROR: /opt/honeypot/.env missing (cp .env.example .env)"; exit 1; }
chmod 600 .env

echo "==> Installing packages"
apt-get update -q
DEBIAN_FRONTEND=noninteractive apt-get install -y -q docker.io docker-compose-v2 python3 jq yara git
systemctl enable --now docker

echo "==> Adding 1 GB swap (1 GB RAM droplet)"
if ! swapon --show | grep -q /swapfile; then
  fallocate -l 1G /swapfile && chmod 600 /swapfile && mkswap /swapfile && swapon /swapfile
  grep -q /swapfile /etc/fstab || echo '/swapfile none swap sw 0 0' >> /etc/fstab
fi

echo "==> Creating data folders (Cowrie runs as UID 999 inside the container)"
mkdir -p data/cowrie/{log,downloads,tty} out
chown -R 999:999 data/cowrie
chmod 755 data data/cowrie data/cowrie/log
chmod 750 data/cowrie/downloads   # malware: readable by root only (and cowrie)

echo "==> Starting Cowrie"
docker compose -f infra/docker-compose.yml up -d

echo "==> Egress firewall + alerter service"
cp infra/systemd/honeypot-egress.service infra/systemd/honeypot-alerter.service /etc/systemd/system/
systemctl daemon-reload
systemctl enable --now honeypot-egress.service
systemctl enable --now honeypot-alerter.service

echo "==> Cron jobs (health check, daily digest, log compression)"
install -m 644 infra/honeypot.cron /etc/cron.d/honeypot

sleep 5
echo
docker ps --filter name=cowrie --format 'cowrie: {{.Status}}'
systemctl is-active honeypot-alerter >/dev/null && echo "alerter: running"
echo "Done. Next: sudo python3 scripts/healthcheck.py --test   (Telegram test message)"
