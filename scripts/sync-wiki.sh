#!/usr/bin/env bash
set -euo pipefail

# Helper script for manual synchronization between ./wiki/ and GitHub Wiki
REPO_URL="${WIKI_REPO_URL:-https://github.com/cbrosius/homelab_cert_manager.wiki.git}"
ACTION="${1:-pull}"
TMP_DIR="$(mktemp -d)"

cleanup() {
    rm -rf "$TMP_DIR"
}
trap cleanup EXIT

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"
WIKI_DIR="$ROOT_DIR/wiki"

mkdir -p "$WIKI_DIR"

case "$ACTION" in
    pull)
        echo "Cloning remote wiki from $REPO_URL..."
        git clone "$REPO_URL" "$TMP_DIR/wiki"
        echo "Copying files to $WIKI_DIR (excluding .git)..."
        if command -v rsync >/dev/null 2>&1; then
            rsync -av --exclude='.git' "$TMP_DIR/wiki/" "$WIKI_DIR/"
        else
            cp -r "$TMP_DIR/wiki/"* "$WIKI_DIR/"
            rm -rf "$WIKI_DIR/.git"
        fi
        echo "Wiki pulled successfully into $WIKI_DIR"
        ;;
    push)
        echo "Cloning remote wiki from $REPO_URL..."
        git clone "$REPO_URL" "$TMP_DIR/wiki"
        echo "Syncing local files to clone..."
        if command -v rsync >/dev/null 2>&1; then
            rsync -av --delete --exclude='.git' "$WIKI_DIR/" "$TMP_DIR/wiki/"
        else
            find "$TMP_DIR/wiki" -mindepth 1 -not -name '.git' -delete
            cp -r "$WIKI_DIR/"* "$TMP_DIR/wiki/"
        fi
        cd "$TMP_DIR/wiki"
        if [ -n "$(git status --porcelain)" ]; then
            git add .
            git commit -m "Manual sync from repository wiki/"
            git push origin master || git push origin main
            echo "Wiki pushed successfully."
        else
            echo "No changes to push."
        fi
        ;;
    *)
        echo "Usage: $0 [pull|push]"
        exit 1
        ;;
esac
