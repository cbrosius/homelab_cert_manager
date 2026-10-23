#!/bin/sh
set -e

# If running as root inside container, attempt to adapt permissions and switch to appuser
if [ "$(id -u)" = "0" ]; then
    # Attempt to transfer ownership and permissions if possible
    if [ -d "/app/data" ]; then
        chown -R appuser:appgroup /app/data 2>/dev/null || true
        chmod -R u+rwX,g+rX /app/data 2>/dev/null || true
    fi

    # Verify if appuser (UID 10001) can read settings.json (if present) and write to /app/data
    CAN_READ_CONFIG=1
    if [ -f "/app/data/settings.json" ]; then
        if ! su-exec appuser test -r "/app/data/settings.json" 2>/dev/null; then
            CAN_READ_CONFIG=0
        fi
    fi

    CAN_WRITE_DATA=0
    if su-exec appuser test -w "/app/data" 2>/dev/null; then
        CAN_WRITE_DATA=1
    fi

    if [ "$CAN_READ_CONFIG" = "1" ] && [ "$CAN_WRITE_DATA" = "1" ]; then
        exec su-exec appuser "$@"
    else
        echo "[homelab_cert_manager] Notice: Volume /app/data is not accessible by unprivileged user (UID 10001)."
        echo "[homelab_cert_manager] Continuing as container root to preserve compatibility with legacy host volume."
        exec "$@"
    fi
fi

exec "$@"
