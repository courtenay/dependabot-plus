#!/bin/bash
set -e

SANDBOX_USER="sandbox"
SANDBOX_HOME=$(eval echo "~$SANDBOX_USER")

# --- Lay canary files (as root, in sandbox user's home) ---
if [ -n "$CANARY_FILES_JSON" ]; then
    echo "$CANARY_FILES_JSON" | python3 -c "
import json, sys, os
home = '$SANDBOX_HOME'
files = json.load(sys.stdin)
for path, content in files.items():
    # Remap /root/ paths to sandbox user's home
    path = path.replace('/root', home)
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, 'w') as f:
        f.write(content)
    # Make readable by sandbox user
    os.chmod(path, 0o644)
"
fi

# --- Start inotifywait on canary file paths (as root) ---
CANARY_LOG="/var/log/canary.log"
touch "$CANARY_LOG"

if [ -n "$CANARY_WATCH_PATHS" ]; then
    echo "$CANARY_WATCH_PATHS" | while read -r p; do
        # Remap /root/ to sandbox user home
        p="${p//\/root/$SANDBOX_HOME}"
        if [ -f "$p" ]; then
            inotifywait -m -q -e access -e open -e close_nowrite "$p" >> "$CANARY_LOG" 2>&1 &
        fi
    done
fi

# --- Start tcpdump if in monitor mode (requires root) ---
NETWORK_LOG="/var/log/network.log"
touch "$NETWORK_LOG"

if [ "$MONITOR_NETWORK" = "1" ]; then
    # Capture 1: TCP connections (IPv4, outbound only, skip Docker noise)
    tcpdump -i any -nn -l -q 'ip and tcp' 2>/dev/null | while read -r line; do
        echo "$line" >> /var/log/network.log
    done &
    # Capture 2: DNS queries with full decode — shows actual domain names
    tcpdump -i any -nn -l -v 'udp port 53' 2>/dev/null \
        > /var/log/dns.log &
    # Capture 3: ASCII payload dump — captures HTTP methods, headers, POST bodies
    tcpdump -i any -nn -l -A -s 2048 'tcp port 80 or tcp port 443 or tcp port 8080' ip 2>/dev/null \
        > /var/log/payload.log &
fi

# --- Prepare sudo log ---
touch /var/log/sudo.log
chmod 666 /var/log/sudo.log

# Give monitors a moment to set up
sleep 0.5

# --- Run the install command as unprivileged sandbox user ---
INSTALL_LOG="/var/log/install.log"
INSTALL_EXIT=0
su -s /bin/bash "$SANDBOX_USER" -c "cd /sandbox && $INSTALL_CMD" > "$INSTALL_LOG" 2>&1 || INSTALL_EXIT=$?

# Give a moment for async operations
sleep 2

# --- Kill monitors ---
pkill -f inotifywait 2>/dev/null || true
pkill -f tcpdump 2>/dev/null || true
sleep 0.3

# --- Output results as JSON ---
python3 -c "
import json, os

with open('/var/log/canary.log') as f:
    canary_lines = [l.strip() for l in f if l.strip()]

with open('/var/log/install.log') as f:
    install_log = f.read()

# Parse network captures — log everything, classify later
import re

dns_queries = []
tcp_connections = []

# Parse DNS log — extract queried domain names
if os.path.exists('/var/log/dns.log'):
    with open('/var/log/dns.log') as f:
        for line in f:
            # tcpdump -v shows DNS queries like: A? registry.npmjs.org.
            m = re.search(r'(\w+\?)\s+(\S+)', line)
            if m:
                qtype, domain = m.group(1), m.group(2).rstrip('.')
                dns_queries.append(f'{qtype} {domain}')

# Parse TCP connections — outbound only
if os.path.exists('/var/log/network.log'):
    seen_dests = set()
    with open('/var/log/network.log') as f:
        for line in f:
            line = line.strip()
            if not line or ' In ' in line:
                continue
            # Extract destination IP:port, deduplicate
            m = re.search(r'> (\d+\.\d+\.\d+\.\d+\.\d+):', line)
            if m:
                dest = m.group(1)
                if dest not in seen_dests:
                    seen_dests.add(dest)
                    tcp_connections.append(dest)

# Parse payload captures — extract HTTP methods, hosts, and POST bodies
http_requests = []
if os.path.exists('/var/log/payload.log'):
    with open('/var/log/payload.log') as f:
        content = f.read()
    # Find HTTP request lines (GET /path, POST /path, etc.)
    for m in re.finditer(r'(GET|POST|PUT|DELETE|PATCH) (\S+) HTTP', content):
        method, path = m.group(1), m.group(2)
        # Look for Host header nearby
        host_m = re.search(r'Host:\s*(\S+)', content[m.start():m.start()+500])
        host = host_m.group(1) if host_m else 'unknown'
        entry = {'method': method, 'path': path, 'host': host}
        # For POST/PUT, try to grab the body (first 500 chars after headers)
        if method in ('POST', 'PUT'):
            body_start = content.find('\r\n\r\n', m.start())
            if body_start > 0:
                body = content[body_start+4:body_start+504].strip()
                if body:
                    entry['body_preview'] = body[:500]
        http_requests.append(entry)

# Parse sudo attempts
sudo_attempts = []
if os.path.exists('/var/log/sudo.log'):
    with open('/var/log/sudo.log') as f:
        for line in f:
            line = line.strip()
            if line:
                sudo_attempts.append(line)

result = {
    'install_exit_code': $INSTALL_EXIT,
    'install_log': install_log[-10000:],
    'file_accesses': canary_lines,
    'dns_queries': dns_queries,
    'tcp_connections': tcp_connections,
    'http_requests': http_requests,
    'sudo_attempts': sudo_attempts,
}
print(json.dumps(result))
"
