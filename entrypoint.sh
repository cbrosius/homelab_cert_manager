#!/bin/sh
set -e

# If running as root, fix volume permissions from legacy versions and drop privileges
if [ "$(id -u)" = "0" ]; then
    if [ -d "/app/data" ]; then
        chown -R appuser:appgroup /app/data
    fi
    exec su-exec appuser "$@"
fi

exec "$@"
