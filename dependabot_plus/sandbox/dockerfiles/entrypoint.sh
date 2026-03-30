#!/bin/bash
set -e

# --- Lay canary files ---
# CANARY_FILES_JSON is set by the runner as a JSON object: {path: content}
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
    # CANARY_WATCH_PATHS is a newline-separated list of file paths
    echo "$CANARY_WATCH_PATHS" | while read -r p; do
        if [ -f "$p" ]; then
            inotifywait -m -q -e access -e open -e close_nowrite "$p" >> "$CANARY_LOG" 2>&1 &
        fi
    done
fi

# Give inotifywait a moment to set up watches
sleep 0.5

# --- Run the install command ---
INSTALL_LOG="/var/log/install.log"
INSTALL_EXIT=0
eval "$INSTALL_CMD" > "$INSTALL_LOG" 2>&1 || INSTALL_EXIT=$?

# Give a moment for any post-install hooks to trigger file access
sleep 1

# --- Kill inotifywait processes ---
pkill -f inotifywait 2>/dev/null || true
sleep 0.2

# --- Output results as JSON ---
python3 -c "
import json

with open('/var/log/canary.log') as f:
    canary_lines = [l.strip() for l in f if l.strip()]

with open('/var/log/install.log') as f:
    install_log = f.read()

result = {
    'install_exit_code': $INSTALL_EXIT,
    'install_log': install_log[-10000:],
    'file_accesses': canary_lines,
}
print(json.dumps(result))
"
