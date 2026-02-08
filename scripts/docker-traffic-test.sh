#!/bin/bash
# Send test traffic to HybridGuard (run on host with Start Monitoring).
# Usage: ./scripts/docker-traffic-test.sh [HOST_IP]
# If HOST_IP is omitted, uses this machine's primary IP.
HOST_IP="${1:-$(hostname -I | awk '{print $1}')}"
echo "Sending test traffic to $HOST_IP (run HybridGuard on host with Start Monitoring)"
docker run --rm -it --cap-add=NET_RAW alpine/curl sh -c "
  apk add --no-cache nmap hping3 2>/dev/null
  echo '=== Port scan ===' && nmap -sT -F $HOST_IP
  echo '=== SYN flood (5s) ===' && timeout 5 hping3 -S -p 80 --flood $HOST_IP 2>/dev/null || true
  echo '=== SQLi-like HTTP ===' && curl -s -o /dev/null 'http://$HOST_IP/?id=1%20union%20select%20*'
"
echo "Check HybridGuard GUI for alerts (Port Scan, SYN Flood, SQL Injection, etc.)."
