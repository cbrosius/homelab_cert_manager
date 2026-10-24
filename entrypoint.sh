#!/bin/sh
set -e

# Define target user and group (match the user created in Dockerfile)
APP_USER="${APP_USER:-appuser}"
APP_GROUP="${APP_GROUP:-appgroup}"

echo "[entrypoint] Starting homelab_cert_manager as UID $(id -u) (GID $(id -g))..."

# If running as root, migrate file ownership and drop privileges
if [ "$(id -u)" = '0' ]; then
    mkdir -p /app/data
    echo "[entrypoint] Running as root. Migrating ownership and permissions on /app/data..."

    # Attempt to transfer ownership and permissions
    chown -R "$APP_USER:$APP_GROUP" /app/data 2>/dev/null || true
    chmod -R u+rwX,g+rwX /app/data 2>/dev/null || true

    if [ -f /app/app.log ]; then
        chown "$APP_USER:$APP_GROUP" /app/app.log 2>/dev/null || true
        chmod 664 /app/app.log 2>/dev/null || true
    fi

    # Verify if target user can read settings.json (if present) and write to /app/data
    CAN_READ_SETTINGS=1
    if [ -f /app/data/settings.json ]; then
        if ! su-exec "$APP_USER:$APP_GROUP" test -r /app/data/settings.json 2>/dev/null; then
            CAN_READ_SETTINGS=0
        fi
    fi

    CAN_WRITE_DATA=0
    if su-exec "$APP_USER:$APP_GROUP" test -w /app/data 2>/dev/null; then
        CAN_WRITE_DATA=1
    fi

    if [ "$CAN_READ_SETTINGS" = "1" ] && [ "$CAN_WRITE_DATA" = "1" ]; then
        echo "[entrypoint] Permissions verified. Dropping privileges to $APP_USER..."
        exec su-exec "$APP_USER:$APP_GROUP" "$@"
    else
        echo "[entrypoint] WARNING: Volume /app/data is not fully accessible by $APP_USER (UID $(id -u "$APP_USER"))."
        echo "[entrypoint] Host mount permissions or filesystem (e.g. NFS root_squash, CIFS) prevented full migration."
        echo "[entrypoint] Falling back to running as container root to preserve compatibility with host volume."
        exec "$@"
    fi
else
    echo "[entrypoint] Container started with non-root UID $(id -u)."
    if [ -f /app/data/settings.json ] && [ ! -r /app/data/settings.json ]; then
        echo "[entrypoint] ERROR: /app/data/settings.json exists but is not readable by UID $(id -u)."
        echo "[entrypoint] If a custom 'User' is set in Portainer/Docker, please remove it so the container can start as root to migrate permissions, or run 'sudo chown -R 10001:10001 ./data' on the host."
    fi
    exec "$@"
fi
