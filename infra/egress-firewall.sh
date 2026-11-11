#!/usr/bin/env bash
# Limit what the Cowrie container can connect OUT to.
#
# Cowrie never runs attacker code, but it DOES fetch files when an attacker
# types wget/curl (that is how we capture malware). So outbound HTTP must stay
# open, but we block things that could get the droplet abused or reported:
#   - SMTP (spam)                         - the DigitalOcean metadata service
#   - private networks / DO VPC (pivoting)
#
# Docker-published ports bypass UFW, so we use Docker's DOCKER-USER chain.
# Run by honeypot-egress.service at boot (after Docker starts).
set -euo pipefail
NET=172.30.0.0/24
add() { iptables -C DOCKER-USER "$@" 2>/dev/null || iptables -I DOCKER-USER "$@"; }

add -s "$NET" -p tcp -m multiport --dports 25,465,587 -m conntrack --ctstate NEW -j DROP
for dst in 10.0.0.0/8 172.16.0.0/12 192.168.0.0/16 169.254.0.0/16 100.64.0.0/10; do
  add -s "$NET" -d "$dst" -m conntrack --ctstate NEW -j DROP
done
echo "Egress rules applied:"
iptables -S DOCKER-USER
