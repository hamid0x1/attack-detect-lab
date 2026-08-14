#!/bin/bash

# Get the directory this script lives in (same trick as sync-logs.sh)
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
LOCAL_LOG="$SCRIPT_DIR/logs/access.log"

# Clear the log inside the DVWA container
docker exec dvwa bash -c "> /var/log/apache2/access.log"

# Also clear the local synced copy immediately, so you don't wait for the next sync cycle
> "$LOCAL_LOG"

echo "Logs cleared — container and local copy."
