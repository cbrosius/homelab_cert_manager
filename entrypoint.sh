#!/bin/sh
set -e

# Define target user and group (match the user created in Dockerfile)
APP_USER="${APP_USER:-appuser}"
APP_GROUP="${APP_GROUP:-appgroup}"

# If running as root, migrate file ownership and drop privileges
if [ "$(id -u)" = '0' ]; then
    mkdir -p /app/data
    chown -R "$APP_USER:$APP_GROUP" /app/data

    if [ -f /app/app.log ]; then
        chown "$APP_USER:$APP_GROUP" /app/app.log
    fi

    # Drop root privileges and replace shell process with the Go application
    if command -v su-exec >/dev/null 2>&1; then
        exec su-exec "$APP_USER:$APP_GROUP" "$@"
    elif command -v gosu >/dev/null 2>&1; then
        exec gosu "$APP_USER:$APP_GROUP" "$@"
    fi
fi

# Fallback if container was started with explicit --user flag
exec "$@"
