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

# --- Watch for writes/creates outside the install dir and tmp (as root) ---
# Detector: dependabot_plus/sandbox/detectors.py (InotifyWriteDetector). It owns
# the allow/deny policy; this only records raw events as "EVENTS|path".
WRITES_LOG="/var/log/writes.log"
touch "$WRITES_LOG"
if [ -n "$WRITE_WATCH_PATHS" ]; then
    echo "$WRITE_WATCH_PATHS" | while read -r p; do
        p="${p//\/root/$SANDBOX_HOME}"
        if [ -d "$p" ]; then
            inotifywait -m -r -q -e create -e modify -e close_write -e moved_to \
                --format '%e|%w%f' "$p" >> "$WRITES_LOG" 2>&1 &
        fi
    done
fi

# --- Start tcpdump if in monitor mode (requires root) ---
NETWORK_LOG="/var/log/network.log"
touch "$NETWORK_LOG"

if [ "$MONITOR_NETWORK" = "1" ]; then
    # Capture 1: TCP connections (IPv4, outbound only, skip Docker noise)
    tcpdump -i any -nn -tt -l -q 'ip and tcp' 2>/dev/null | while read -r line; do
        echo "$line" >> /var/log/network.log
    done &
    # Capture 2: DNS queries with full decode — shows actual domain names
    tcpdump -i any -nn -tt -l -v 'udp port 53' 2>/dev/null \
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

# Events after this instant count as "post_install" (detached/background activity)
INSTALL_END=$(date +%s.%N)

# Give a moment for async operations
sleep 2

# --- Kill monitors ---
pkill -f inotifywait 2>/dev/null || true
pkill -f tcpdump 2>/dev/null || true
sleep 0.3

# --- Output results as JSON (parsing lives in collect_report.py, unit tested) ---
python3 /collect_report.py "$INSTALL_EXIT" "$INSTALL_END"
