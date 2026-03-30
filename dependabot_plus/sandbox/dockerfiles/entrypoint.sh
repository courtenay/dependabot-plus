#!/bin/bash
set -e

# --- Lay canary files ---
if [ -n "$CANARY_FILES_JSON" ]; then
    echo "$CANARY_FILES_JSON" | python3 -c "
import json, sys, os
files = json.load(sys.stdin)
for path, content in files.items():
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, 'w') as f:
        f.write(content)
"
fi

# --- Start inotifywait on canary file paths ---
CANARY_LOG="/var/log/canary.log"
touch "$CANARY_LOG"

if [ -n "$CANARY_WATCH_PATHS" ]; then
    echo "$CANARY_WATCH_PATHS" | while read -r p; do
        if [ -f "$p" ]; then
            inotifywait -m -q -e access -e open -e close_nowrite "$p" >> "$CANARY_LOG" 2>&1 &
        fi
    done
fi

# --- Start tcpdump if in monitor mode ---
NETWORK_LOG="/var/log/network.log"
touch "$NETWORK_LOG"
TCPDUMP_PID=""

if [ "$MONITOR_NETWORK" = "1" ]; then
    # Capture DNS queries and TCP SYN packets
    tcpdump -i any -nn -l -q 2>/dev/null | tee /var/log/tcpdump_raw.log | python3 -u -c "
import sys, re, json
for line in sys.stdin:
    line = line.strip()
    if not line:
        continue
    with open('/var/log/network.log', 'a') as f:
        f.write(line + '\n')
" &
    TCPDUMP_PID=$!
fi

# Give monitors a moment to set up
sleep 0.5

# --- Run the install command ---
INSTALL_LOG="/var/log/install.log"
INSTALL_EXIT=0
eval "$INSTALL_CMD" > "$INSTALL_LOG" 2>&1 || INSTALL_EXIT=$?

# Give a moment for async operations
sleep 2

# --- Kill monitors ---
pkill -f inotifywait 2>/dev/null || true
if [ -n "$TCPDUMP_PID" ]; then
    kill "$TCPDUMP_PID" 2>/dev/null || true
fi
sleep 0.3

# --- Output results as JSON ---
python3 -c "
import json, re, os

with open('/var/log/canary.log') as f:
    canary_lines = [l.strip() for l in f if l.strip()]

with open('/var/log/install.log') as f:
    install_log = f.read()

# Parse network captures
dns_queries = []
tcp_connections = []

if os.path.exists('/var/log/network.log'):
    with open('/var/log/network.log') as f:
        for line in f:
            line = line.strip()
            # DNS queries show domain names in tcpdump output
            if '.depbot-canary.' in line or 'A?' in line:
                dns_queries.append(line)
            # Look for any DNS-related lines
            elif ' > ' in line and ('.53:' in line or '.53 ' in line):
                dns_queries.append(line)
            # TCP SYN to non-local addresses
            elif ' > ' in line and 'S' in line:
                tcp_connections.append(line)
            # Any other network line
            elif ' > ' in line:
                tcp_connections.append(line)

result = {
    'install_exit_code': $INSTALL_EXIT,
    'install_log': install_log[-10000:],
    'file_accesses': canary_lines,
    'dns_queries': dns_queries,
    'tcp_connections': tcp_connections,
}
print(json.dumps(result))
"
