# AGENTS.md – Project Principles & Guidelines for AI Agents

## 1. Project Overview
**Homelab Cert Manager** is a lightweight, self-contained web application written in Go to create and manage an internal Root CA and SSL/TLS certificates for homelab environments.

## 2. Core Philosophy (Non-Negotiable)
1. **Simplicity First:** The tool must remain dead simple for the end user ("Click and Done"). Do not introduce background automation, cronjobs, ACME servers, or complex PKI hierarchies unless explicitly requested.
2. **Zero External Runtime Dependencies by Default:** The application must work completely standalone and offline out of the box using local file storage (`data/`), local assets (`static/`), and local documentation (`wiki/`).
3. **Strictly Opt-In Integrations:** External integrations (such as OIDC / Pocket ID) must always be strictly optional. If disabled, the tool must behave as if the integration does not exist.
4. **Prevent Chicken-and-Egg Lockouts:** Because this tool issues the certificates that other homelab services (like an OIDC provider) rely on, **never** completely disable or remove the local emergency admin login.
5. **Minimal Dependency Footprint:** Prefer the Go standard library (`net/http`, `crypto/x509`, `crypto/rsa`, `encoding/pem`, `html/template`, `encoding/json`, `testing`) over third-party packages whenever possible.

---

## 3. Architecture & File Structure
Keep the flat, readable package structure (`package main`). Do not over-engineer into nested `pkg/` or `internal/` enterprise folder structures.

- **Consolidated Single-Package Architecture:** All Go source files and unit tests reside in `cmd/cert_manager/` (`package main`). To prevent repository clutter and avoid unnecessary layers of indirection (`cmd/` + `internal/`), do **not** introduce an `internal/` or `pkg/` folder unless the project evolves to produce multiple independent binaries.

- `cmd/cert_manager/main.go`: HTTP/HTTPS server setup, routing, session/auth middleware, and HTML template rendering.
- `cmd/cert_manager/rootcert.go`: Root CA generation, loading, and validation.
- `cmd/cert_manager/certificate.go`: Service certificate generation, CSR parsing/signing, listing, and file management.
- `cmd/cert_manager/settings.go`: Reading and writing configuration in `data/settings.json`.
- `cmd/cert_manager/oidc.go`: Optional OpenID Connect / Pocket ID authentication flow (with PKCE) and custom Root CA trust pool.
- `cmd/cert_manager/wiki.go`: Offline Markdown rendering for the bundled documentation (`wiki/`) served under `/help`.
- `cmd/cert_manager/*_test.go`: Unit and integration tests using the standard `testing` package.
- `templates/`: Server-side rendered Go HTML templates (`*.html`).
- `static/`: Local frontend assets (Materialize CSS, JS, icons). **No external CDNs** (must work offline/air-gapped).
- `wiki/`: Local Markdown documentation synchronized with the GitHub Wiki (`homelab_cert_manager.wiki.git`).
- `data/`: Runtime directory for `settings.json`, `rootCA.crt`, `rootCA.key`, and issued certificates (excluded from Git).

---

## 4. Coding, UI & Security Standards

### Go Backend
- **Error Handling:** Always handle errors explicitly. Never use `panic()` in HTTP handlers; return meaningful user feedback or log errors cleanly.
- **File Permissions:**
  - Private keys (`*.key`) and `settings.json` must be written with restrictive permissions (`0600`).
  - Public certificates (`*.pem` / `*.crt`) and CSRs (`*.csr`) should use `0644`.
- **Path Traversal Protection:** Always sanitize filenames (`filepath.Base`) before reading or deleting files in `data/` or rendering Markdown pages from `wiki/`.
- **Internal CA Trust:** When making outbound HTTPS calls (e.g., to an OIDC Issuer), always append `data/rootCA.crt` (if present) to the `x509.SystemCertPool()` so the container trusts certificates issued by itself.

### Frontend & Contextual Offline Help
- **Offline Capability:** Never load CSS, fonts, images, or JS from external CDNs. Keep all assets local in `static/` and `wiki/`.
- **Theme Consistency:** Follow the existing Materialize CSS structure and support both **Dark Mode and Light Mode** across all views, modals, and the integrated help viewer (`templates/help.html`).
- **No Frontend Build Step:** Use plain HTML templates and vanilla JS. Do not introduce npm, Webpack, Vite, or SPA frameworks.
- **Same-Window Contextual Help (`?`):**
  - Help links and the main "Help" menu item open in the **current browser window/tab** (do **not** use `target="_blank"`), providing a consistent top navigation bar to return to the Certificate List (`/`) or Settings (`/settings`).
  - Every configuration section, modal, and **every individual option on the Settings page (`templates/settings.html`)** must include a contextual `?` help icon (`help_outline`) deep-linking to its exact section in `/help/<Page>#<anchor>` (specifically `/help/Settings#<setting-anchor>` for settings).

### Docker & Deployment
- **Non-Root Execution:** The application must run as an unprivileged user (`appuser:appgroup`) at runtime.
- **Seamless Upgrades:** File ownership migrations on `/app/data` must be handled automatically in `entrypoint.sh` via privilege dropping (`su-exec` / `gosu`) before starting the Go binary.
- **Bundle Docs:** Ensure `Dockerfile` copies `templates/`, `static/`, and `wiki/` into the runtime image.

---

## 5. Testing Standards (`go test`)
- **Standard Library Only:** Use Go's built-in `testing` and `net/http/httptest` packages. Do not add third-party assertion libraries.
- **Strict Test Isolation (`t.TempDir()`):** Tests must **never** read from, write to, or modify the real `./data/` directory. Always use `t.TempDir()`.
- **Required Test Coverage:**
  - **Cryptography & CSR:** Root CA generation, service cert chain verification, CSR signing (`SignCSR` preserving Subject & SANs without creating a `.key` file), invalid PEM/CSR rejection, and `0600` key file permissions.
  - **OIDC & PKCE:** Redirect URL generation with PKCE (`code_challenge`, `code_challenge_method=S256`), optional empty client secret support, and custom Root CA pool loading.
  - **Integrated Help / Wiki:** Verify Markdown rendering under `/help`, automatic heading `#anchor` ID generation, and strict path traversal rejection.

---

## 6. Documentation, Wiki & Git Hygiene (Definition of Done)
A task or feature is **NOT complete** until all of the following steps are fulfilled:
1. **Update Offline Wiki (`wiki/*.md`):** Whenever a feature, workflow, environment variable, or **Settings option** is added or modified, update the corresponding Markdown page in `wiki/` (especially `wiki/Settings.md` with a dedicated `##` / `###` heading so `#anchors` work) and link the matching `?` help icon in the UI.
2. **Keep `README.md`, `CHANGELOG` & `todo.txt` in Sync:**
   - Record every user-facing feature, fix, or security change in `CHANGELOG`.
   - Make surgical updates to `README.md` when setup steps or environment variables change.
   - Remove or check off completed items in `todo.txt`.
3. **Never Commit Runtime Files:** Ensure `app.log`, `data/*.crt`, `data/*.pem`, `data/*.key`, and local `data/settings.json` are never staged or committed.
4. **Run Pre-Commit Verification:**
   - `go vet ./...`
   - `go test -v ./...`
   - `go build ./...`