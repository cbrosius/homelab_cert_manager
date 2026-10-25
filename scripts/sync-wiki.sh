#!/usr/bin/env bash
# scripts/sync-wiki.sh - Synchronize local wiki documentation with GitHub Wiki
set -euo pipefail

WIKI_REPO_URL="${WIKI_REPO_URL:-https://github.com/cbrosius/homelab_cert_manager.wiki.git}"
ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
WIKI_DIR="${ROOT_DIR}/wiki"
TEMP_DIR="/tmp/homelab_cert_manager_wiki_sync"

ACTION="${1:-}"

if [[ -z "${ACTION}" || ( "${ACTION}" != "pull" && "${ACTION}" != "push" ) ]]; then
    echo "Usage: $0 [pull|push]"
    echo ""
    echo "  pull  - Fetch latest documentation from GitHub Wiki and update local wiki/"
    echo "  push  - Push local wiki/ documentation changes to GitHub Wiki"
    exit 1
fi

if [[ "${ACTION}" == "pull" ]]; then
    echo "==> Pulling latest wiki pages from ${WIKI_REPO_URL}..."
    rm -rf "${TEMP_DIR}"
    git clone --depth=1 "${WIKI_REPO_URL}" "${TEMP_DIR}"
    
    mkdir -p "${WIKI_DIR}"
    # Copy markdown files, preserving local work
    rsync -av --exclude='.git/' "${TEMP_DIR}/" "${WIKI_DIR}/"
    rm -rf "${TEMP_DIR}"
    echo "==> Wiki pull completed successfully."

elif [[ "${ACTION}" == "push" ]]; then
    echo "==> Pushing local wiki pages to ${WIKI_REPO_URL}..."
    rm -rf "${TEMP_DIR}"
    git clone "${WIKI_REPO_URL}" "${TEMP_DIR}"
    
    # Sync files from wiki/ into temp git clone
    rsync -av --delete --exclude='.git/' "${WIKI_DIR}/" "${TEMP_DIR}/"
    
    cd "${TEMP_DIR}"
    if [[ -n "$(git status --porcelain)" ]]; then
        git add -A
        git commit -m "docs(wiki): sync documentation from main repository"
        git push origin master || git push origin main
        echo "==> Wiki pushed successfully to GitHub."
    else
        echo "==> No changes detected between local wiki/ and remote wiki."
    fi
    rm -rf "${TEMP_DIR}"
fi
