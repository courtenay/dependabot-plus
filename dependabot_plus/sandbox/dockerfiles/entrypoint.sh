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
    tcpdump -i any -nn -l -q 2>/dev/null | while read -r line; do
        echo "$line" >> /var/log/network.log
    done &
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

# Parse network captures
dns_queries = []
tcp_connections = []

if os.path.exists('/var/log/network.log'):
    with open('/var/log/network.log') as f:
        for line in f:
            line = line.strip()
            if '.53:' in line or '.53 ' in line:
                dns_queries.append(line)
            elif ' > ' in line:
                tcp_connections.append(line)

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
    'sudo_attempts': sudo_attempts,
}
print(json.dumps(result))
"
