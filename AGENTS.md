# Project Rules & Guidelines

## 1. Project Overview
**Homelab Cert Manager** is a lightweight, self-contained web application written in Go to create and manage an internal Root CA and SSL/TLS certificates for homelab environments.

## 2. Core Philosophy (Non-Negotiable)
1. **Simplicity First:** The tool must remain dead simple for the end user ("Click and Done"). Do not introduce background automation, cronjobs, ACME servers, or complex PKI hierarchies unless explicitly requested.
2. **Zero External Runtime Dependencies by Default:** The application must work completely standalone out of the box using local file storage (`data/`) and local authentication.
3. **Strictly Opt-In Integrations:** External integrations (such as OIDC / Pocket ID) must always be strictly optional. If disabled, the tool must behave as if the integration does not exist.
4. **Prevent Chicken-and-Egg Lockouts:** Because this tool issues the certificates that other homelab services (like an OIDC provider) rely on, **never** completely disable or remove the local emergency admin login.
5. **Minimal Dependency Footprint:** Prefer the Go standard library (`net/http`, `crypto/x509`, `crypto/rsa`, `encoding/pem`, `html/template`, `encoding/json`) over third-party packages whenever possible.

## 3. Git & Commits
- **NEVER perform git commits** (`git commit`, etc.).
- The user will **ALWAYS** perform all git commits themselves.
- The assistant may propose changes, stage files if asked, run tests, or prepare PR links/descriptions, but must never commit code to the repository.

## 4. Architecture & Repository Layout
- **Consolidated Single-Package Architecture:** All Go source files and unit tests reside in `cmd/cert_manager/` (`package main`). To prevent repository clutter and avoid unnecessary layers of indirection (`cmd/` + `internal/`), do **not** introduce an `internal/` or `pkg/` folder unless the project evolves to produce multiple independent binaries.
- `cmd/cert_manager/`: Application binary entrypoint and domain logic (Gin router, handlers, middlewares, crypto logic, and `*_test.go` unit tests).
- `docker/`: Container build files (`Dockerfile`, `entrypoint.sh`).
- `data/`: Local certificate storage (`certs/`, `root-cert/`, `certmanager-cert/`) and configuration (`settings.json`).
- `static/`: Static web assets (CSS, JS, fonts, images).
- `templates/`: HTML templates for Gin web interface.

## 5. Technical Stack
- **Go 1.27+**: Framework: Gin Gonic (`gin-gonic/gin`).
- **Configuration**: Viper (`spf13/viper`).
- **Security & Crypto**: `crypto/x509`, `crypto/rsa`, `software.sslmate.com/src/go-pkcs12`, `bcrypt`.
- **Sessions & Protection**: Gorilla sessions, Gorilla CSRF, custom rate limiting, and security headers.
- **SSO**: OIDC authentication (`go-oidc/v3`, `oauth2`).

## 6. Coding & Security Standards

### Go Backend
- **Error Handling:** Always handle errors explicitly. Never use `panic()` in HTTP handlers; return meaningful user feedback or log errors cleanly.
- **File Permissions:**
  - Private keys (`*.key`) and `settings.json` must be written with restrictive permissions (`0600`).
  - Public certificates (`*.pem` / `*.crt`) and CSRs (`*.csr`) should use `0644`.
- **Path Traversal Protection:** Always sanitize filenames (e.g., using `filepath.Base` or custom sanitize functions) before reading or deleting certificate files from `data/`.
- **Internal CA Trust:** When making outbound HTTPS calls (e.g., to an OIDC Issuer), always append root CA (if present) to the `x509.SystemCertPool()` so the container trusts certificates issued by itself.

### Frontend & UI
- **Offline Capability:** Never load CSS, fonts, or JS from external CDNs. Keep all assets local in `static/`.
- **Consistency:** Follow the existing Materialize CSS structure and support both **Dark Mode and Light Mode** across all new modals, buttons, and tables.
- **No Frontend Build Step:** Use plain HTML templates and vanilla JS. Do not introduce npm, Webpack, Vite, or SPA frameworks.

### Docker & Deployment
- **Non-Root Execution:** The application must run as an unprivileged user (`appuser:appgroup`) at runtime.
- **Seamless Upgrades:** File ownership migrations on `/app/data` must be handled automatically in `entrypoint.sh` via privilege dropping (`su-exec` / `gosu`) before starting the Go binary.

## 7. Development & Testing
- Run all tests from the repository root: `go test ./...`
- Verify builds: `go build ./cmd/cert_manager`

## 8. Documentation, Changelog & Git Hygiene (Definition of Done)
- **Keep `CHANGELOG` Updated:** Every user-facing change, new feature, bugfix, or security improvement must be added to `CHANGELOG` following its existing format.
- **Keep `README.md` & `todo.txt` in Sync:**
  - Whenever new features, environment variables, ports, or workflows (like CSR signing or Pocket ID / OIDC setup) are added, update `README.md` accordingly. Make surgical updates rather than rewriting unrelated sections.
  - If a completed task is listed in `todo.txt`, mark it as done or remove it.
- **Never Commit Runtime Files:** Ensure `app.log`, `data/*.crt`, `data/*.key`, and local `data/settings.json` are never staged or committed.
- **Pre-Commit Verification:** Before considering any task complete, always run:
  1. `go vet ./...`
  2. `go test -v ./...`
  3. `go build ./...`