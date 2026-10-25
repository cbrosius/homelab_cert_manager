# Installation and Deployment Guide

HomeLab Cert Manager can be deployed quickly via Docker, Docker Compose, or compiled directly from source.

---

## 1. Docker Deployment (Recommended)

### Quick Run via Docker CLI

```bash
docker run -d \
  --name homelab_cert_manager \
  --restart unless-stopped \
  -p 8443:8443 \
  -v ./data:/app/data \
  ghcr.io/cbrosius/homelab_cert_manager/homelab_cert_manager:latest
```

---

## 2. Docker Compose

For homelab orchestrators like Portainer, CasaOS, or standard `docker compose`, create a `docker-compose.yml` file:

```yaml
version: "3.8"

services:
  cert-manager:
    image: ghcr.io/cbrosius/homelab_cert_manager/homelab_cert_manager:latest
    container_name: homelab_cert_manager
    restart: unless-stopped
    ports:
      - "8443:8443"
    volumes:
      - data:/app/data
    environment:
      # Optional: Pre-configure OIDC Single Sign-On
      - OIDC_ENABLED=false
      # - OIDC_ISSUER_URL=https://pocket-id.homelab.local
      # - OIDC_CLIENT_ID=homelab-cert-manager
      # - OIDC_CLIENT_SECRET=your_oidc_client_secret
      # - OIDC_REDIRECT_URL=https://certs.homelab.local:8443/auth/oidc/callback
volumes:
  data:
```

Start the service with:

```bash
docker compose up -d
```

---

## 3. Container Security & User Privileges

Starting with version `0.4`, the Docker container runs securely under an unprivileged user:
- **User:** `appuser` (UID: `10001`)
- **Group:** `appgroup` (GID: `10001`)

### Automatic Migration from Legacy Containers (Root UID 0)

Earlier releases ran directly as `root` (UID 0), creating files owned by `root:root`. 

The included Docker `entrypoint.sh` automatically detects if the container is started with Docker default permissions (initially running as root before dropping privileges) and:
1. Recursively chowns `/app/data` and `/app/app.log` to `appuser:appgroup` (`10001:10001`).
2. Adjusts permissions to `u+rwX,g+rwX`.
3. Verifies that `appuser` can read and write to the volume.
4. Uses `su-exec` to execute the application process under UID `10001`.

### Manual Host Permission Fix (If Needed)

If your Docker host mounts a directory with restrictive permissions or uses NFS/CIFS shares with root squash, you can fix host directory ownership manually:

```bash
sudo chown -R 10001:10001 ./data
sudo chmod -R 750 ./data
```

> [!WARNING]
> Do not force `user: "0:0"` or custom non-root users without write access to `./data`, as the application requires write permissions to create certificates and persist settings.

---

## 4. Building from Source

To build and run HomeLab Cert Manager locally without Docker:

### Prerequisites
- Go 1.22 or newer
- Git

### Build Instructions

```bash
# Clone the repository
git clone https://github.com/cbrosius/homelab_cert_manager.git
cd homelab_cert_manager

# Download dependencies
go mod download

# Compile the binary
go build -o homelab_cert_manager ./cmd/cert_manager

# Run the binary
./homelab_cert_manager
```

The application creates the `./data/` directory relative to the executable and listens on `https://0.0.0.0:8443`.

---

## 5. Reverse Proxy Configuration

HomeLab Cert Manager serves HTTPS directly on port 8443. When putting it behind a reverse proxy (e.g. Nginx, Traefik, Caddy), configure your proxy to connect upstream over HTTPS.

### Nginx Example

```nginx
server {
    listen 443 ssl http2;
    server_name certs.homelab.local;

    ssl_certificate /path/to/fullchain.pem;
    ssl_certificate_key /path/to/privkey.pem;

    location / {
        proxy_pass https://192.168.1.50:8443;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto https;
        
        # Disable upstream SSL verification for self-signed or internal CA certs
        proxy_ssl_verify off;
    }
}
```

### Traefik (Docker Labels)

```yaml
services:
  cert-manager:
    image: ghcr.io/cbrosius/homelab_cert_manager/homelab_cert_manager:latest
    labels:
      - "traefik.enable=true"
      - "traefik.http.routers.certmgr.rule=Host(`certs.homelab.local`)"
      - "traefik.http.routers.certmgr.entrypoints=websecure"
      - "traefik.http.routers.certmgr.tls=true"
      - "traefik.http.services.certmgr.loadbalancer.server.port=8443"
      - "traefik.http.services.certmgr.loadbalancer.server.scheme=https"
      - "traefik.http.services.certmgr.loadbalancer.serversTransport=insecureTransport@file"
```

---

## 6. Backup & Persistence

All application data, certificates, and configuration are stored inside the `data/` directory:

| Path | Contents |
| :--- | :--- |
| `data/root-cert/` | The Root CA private key and certificate (`HomeLab_Root_CA.pem`, `HomeLab_Root_CA.key`) |
| `data/certs/` | Generated server certificates, external CSR signed certificates, and private keys |
| `data/certmanager-cert/` | HomeLab Cert Manager's own web service certificate |
| `data/settings.json` | General settings, certificate defaults, OIDC configuration, password hash, and timeout values |

> [!CAUTION]
> Regularly back up the `data/` directory. Losing `data/root-cert/HomeLab_Root_CA.key` will permanently break your PKI chain, requiring all issued certificates and client trust stores to be re-provisioned.
