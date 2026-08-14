#!/bin/bash

# Get the directory this script actually lives in, no matter where it's called from
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
LOG_DIR="$SCRIPT_DIR/logs"
LOG_FILE="$LOG_DIR/access.log"

mkdir -p "$LOG_DIR"

while true; do
  docker cp dvwa:/var/log/apache2/access.log "$LOG_FILE"
  sleep 5
done
