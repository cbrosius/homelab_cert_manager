# Homelab Cert Manager

## Overview

Homelab Cert Manager is a Go project designed to manage SSL/TLS certificates for your homelab environment. This tool automates the process of generating, renewing, and distributing certificates, ensuring your services are always secured.

## Features

- **Automated Certificate Management:** Automatically generate and renew SSL/TLS certificates.
- **Ease of Use:** Simple configuration and operation.
- **Integration:** Easily integrates with various homelab services and infrastructure.

## Getting Started

### Prerequisites

- [Go](https://golang.org/doc/install) (version 1.18 or later)
- [Docker](https://docs.docker.com/get-docker/)
- [GitHub Container Registry](https://docs.github.com/en/packages/working-with-a-github-packages-registry/working-with-the-container-registry)

### Installation

1. **Clone the repository:**
    ```sh
    git clone https://github.com/cbrosius/homelab_cert_manager.git
    cd homelab_cert_manager
    ```

2. **Build the Docker image:**
    ```sh
    docker build -t ghcr.io/cbrosius/homelab_cert_manager:latest .
    ```

3. **Run the container:**
    ```sh
    docker run -d --name homelab_cert_manager ghcr.io/cbrosius/homelab_cert_manager:latest
    ```

## Usage

To use Homelab Cert Manager, configure your certificate settings in the `config.yaml` file and start the service. The application will handle the rest, including certificate generation and renewal.

### Configuration

Edit the `config.yaml` file to set up your domain names, email for certificate notifications, and other necessary configurations.

```yaml
domains:
  - example.com
email: your-email@example.com
