#!/bin/bash
# Network monitor sidecar — captures all traffic on the shared network.
# Runs tcpdump until SIGTERM, then parses the pcap and outputs JSON.

PCAP_FILE="/capture/traffic.pcap"
SUMMARY_FILE="/capture/summary.json"

mkdir -p /capture

# Start tcpdump capturing all traffic (not just our container's)
# -U flushes after each packet so we don't lose data on kill
tcpdump -i any -U -w "$PCAP_FILE" 'not port 22' 2>/dev/null &
TCPDUMP_PID=$!

# Wait for SIGTERM (sent by the runner when sandbox finishes)
trap "kill $TCPDUMP_PID 2>/dev/null; wait $TCPDUMP_PID 2>/dev/null" TERM INT
wait $TCPDUMP_PID 2>/dev/null || true

# Give a moment for the file to flush
sleep 0.5

# Parse the pcap into a JSON summary
python3 -c "
import json
import subprocess
import re
import sys

pcap = '$PCAP_FILE'
summary = {'dns_queries': [], 'tcp_connections': [], 'http_requests': [], 'raw_packets': 0}

# Read pcap with tcpdump text output
result = subprocess.run(
    ['tcpdump', '-nn', '-r', pcap, '-q'],
    capture_output=True, text=True,
)
lines = result.stdout.strip().splitlines()
summary['raw_packets'] = len(lines)

# Extract DNS queries
dns_result = subprocess.run(
    ['tcpdump', '-nn', '-r', pcap, 'port 53', '-v'],
    capture_output=True, text=True,
)
for line in dns_result.stdout.splitlines():
    # Match DNS query lines like: A? evil.com
    m = re.search(r'(\S+\?\s+\S+)', line)
    if m:
        summary['dns_queries'].append(m.group(1).strip())

# Extract unique TCP SYN connections (outbound)
tcp_result = subprocess.run(
    ['tcpdump', '-nn', '-r', pcap, 'tcp[tcpflags] & tcp-syn != 0'],
    capture_output=True, text=True,
)
seen_connections = set()
for line in tcp_result.stdout.splitlines():
    # Match: IP src > dst: Flags [S]
    m = re.search(r'IP\s+\S+\s+>\s+(\S+?):', line)
    if m:
        dest = m.group(1)
        if dest not in seen_connections:
            seen_connections.add(dest)
            summary['tcp_connections'].append(dest)

# Extract HTTP Host headers if any
http_result = subprocess.run(
    ['tcpdump', '-nn', '-r', pcap, '-A', 'tcp port 80 or tcp port 443'],
    capture_output=True, text=True,
)
for line in http_result.stdout.splitlines():
    if line.strip().startswith('Host:'):
        host = line.strip().split(':', 1)[1].strip()
        if host not in summary['http_requests']:
            summary['http_requests'].append(host)

print(json.dumps(summary))
" > "$SUMMARY_FILE"

cat "$SUMMARY_FILE"
