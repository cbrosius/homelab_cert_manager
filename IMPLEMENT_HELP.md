# Homelab Cert Manager – Roadmap: Integrated Offline Help & GitHub Wiki Sync (`ROADMAP_HELP.md`)

## Architecture & Implementation Principles
- **Simplicity & Offline-First:** All documentation is bundled locally inside `./wiki/` and rendered directly inside the application. No external runtime dependencies or CDN calls. No multi-language (i18n) complexity.
- **Same-Window Navigation:** Help pages open in the **current browser tab** (just like the Settings page) with a clear navigation button to return to the Certificate List (`/`) or go back to the previous page.
- **Complete Settings Coverage:** Every single configuration option on the Settings page must have a dedicated subsection (`###` / `##` heading with an `#anchor`) in the documentation explaining its exact purpose, format, and impact, linked via a contextual `?` icon next to the input field.
- **Single Source of Truth:** Maintain Markdown files in `./wiki/` and automatically mirror them to the GitHub Wiki (`homelab_cert_manager.wiki.git`) via GitHub Actions.
- **Consolidated Single-Package Architecture:** All Go source files and tests reside in `cmd/cert_manager/` (`package main`).

---

## Milestone 1: Local Wiki Content & Granular Settings Documentation (`wiki/`)
**Goal:** Pull any existing GitHub Wiki pages into `./wiki/`, create structured Markdown documentation for all features, and document every single setting with its own deep-linkable `#anchor`.

- [x] **Initialize `./wiki/` & Docker Bundling**:
  - Pull existing files from `https://github.com/cbrosius/homelab_cert_manager.wiki.git` into `./wiki/` (if available) and provide `scripts/sync-wiki.sh` for manual pull/push.
  - Ensure `.dockerignore` does **not** exclude `wiki/`, and update `Dockerfile` to copy `./wiki` into `/app/wiki` with proper ownership for `appuser:appgroup`.
- [x] **Create Core Feature Wiki Pages (`wiki/*.md`)**:
  - `Home.md`: Overview, quickstart workflow, and table of contents.
  - `Root-Certificate.md`: Creating the Root CA (`#create-root-ca`), renewing/replacing it, and importing/trusting it on Windows, macOS, Linux, iOS, and Android (`#trust-root-ca`).
  - `Certificates.md`: Creating service certificates (`#create-certificate`), configuring DNS & IP Subject Alternative Names (`#san-configuration`), downloading certs/keys, and replacing the Cert Manager's own HTTPS certificate (`#self-certificate`).
  - `CSR-Signing.md`: Uploading or pasting external Certificate Signing Requests (`.csr`) and how CSR signing works (`#sign-csr`).
- [x] **Create Granular Settings Documentation (`wiki/Settings.md`)**:
  - Inspect `cmd/cert_manager/settings.go` and `templates/settings.html` and create a dedicated heading (`##` or `###`) in `wiki/Settings.md` for **every individual setting**, explaining what it does, when it takes effect, and example values:
    - **Certificate & Root CA Defaults:**
      - `#country`: Country Name (2-letter ISO code, e.g., `DE`, `US`) used in the X.509 Subject.
      - `#organization`: Organization Name (`O`) embedded in generated certificates.
      - `#organizational-unit`: Organizational Unit (`OU`) for internal categorization.
      - `#locality` / `#province`: City/Locality (`L`) and State/Province (`ST`) fields.
      - `#root-validity-days` & `#cert-validity-days`: Default validity period in days for Root CA and service certificates (including browser maximum validity notes, e.g., 398 days for Apple/Chrome).
      - `#key-size` (if configurable): RSA key bit length / cryptographic parameters.
    - **Application & Security Settings:**
      - `#change-password`: How changing the local admin password works.
    - **OIDC / Pocket ID Authentication Settings:**
      - `#oidc-enabled`: Enabling/disabling Single Sign-On while retaining the local emergency fallback.
      - `#oidc-issuer-url`: The base discovery URL of Pocket ID / the OIDC provider (and note on automatic internal `rootCA.crt` trust).
      - `#oidc-client-id`: The Client ID registered in Pocket ID.
      - `#oidc-client-secret`: The Client Secret (explaining why it can be left empty when using **PKCE / Public Clients**).
      - `#oidc-redirect-url`: Exact callback URL format (`https://<host>:8443/auth/oidc/callback`).

---

## Milestone 2: In-App Help Viewer (`cmd/cert_manager/wiki.go` & `templates/`)
**Goal:** Render the `wiki/*.md` files inside the main application window with the same look, feel, and navigation pattern as the Settings page.

### 2.1 Backend – Markdown Renderer (`cmd/cert_manager/wiki.go` & `cmd/cert_manager/main.go`)
- [x] **Add `goldmark`**: Add `github.com/yuin/goldmark` configured with `parser.WithAutoHeadingID()` and `extension.GFM` (tables, fenced code blocks).
- [x] **Implement `GET /help` and `GET /help/{page}` (`cmd/cert_manager/wiki.go`)**:
  - Sanitize `{page}` using `filepath.Base` to prevent path traversal; default to `Home` if empty.
  - Render the requested Markdown file from `wiki/{page}.md` into HTML.
  - Rewrite internal Wiki links (e.g., `[Settings](Settings#oidc-enabled)` or `[[Settings]]`) so they point to `/help/Settings#oidc-enabled`.
  - Pass the list of available Wiki pages for sidebar/tab navigation along with the rendered HTML content to the template.

### 2.2 Frontend – Integrated Help View (`templates/help.html`)
- [x] **Create `templates/help.html` Matching `settings.html` Navigation**:
  - Open in the **same browser window/tab** (no `target="_blank"`).
  - Include the standard top navigation bar with a prominent **"Back to Certificates"** (`href="/"`) button and a **"Settings"** (`href="/settings"`) link, matching the navigation UX of `templates/settings.html`.
  - Provide a clean two-column Materialize layout: Wiki page list on the left, rendered documentation on the right.
  - Ensure full compatibility with the existing **Dark Mode / Light Mode** toggle.
  - Highlight the target section smoothly when jumping to an `#anchor`.

---

## Milestone 3: Contextual Help Icons (`?`) Across UI & Every Setting
**Goal:** Add `?` help icons throughout the UI—especially next to **every single option in `templates/settings.html`**—that navigate directly to the corresponding `/help/<Page>#<anchor>` section in the main window.

- [x] **Navigation Bar**: Add a **"Help"** link (`href="/help"`) in the main navigation menu (opening in the same window).
- [x] **Settings Page (`templates/settings.html`)**:
  - Place a contextual `?` icon (`<a href="/help/Settings#<setting-anchor>" class="help-icon" title="Explain this setting"><i class="material-icons tiny">help_outline</i></a>`) next to **every individual input field and toggle** on the Settings page, linking to its exact anchor in `wiki/Settings.md`.
- [x] **Dashboard & Modals (`templates/index.html`, `templates/login.html`, etc.)**:
  - Root CA section $\rightarrow$ `/help/Root-Certificate#trust-root-ca`
  - Create Certificate modal & SAN fields $\rightarrow$ `/help/Certificates#san-configuration`
  - Sign CSR modal $\rightarrow$ `/help/CSR-Signing#sign-csr`
  - Login page (OIDC / Fallback) $\rightarrow$ `/help/Settings#oidc-enabled`

---

## Milestone 4: Tests & Documentation Hygiene
- [x] **Unit Tests (`cmd/cert_manager/wiki_test.go`)**:
  - Test rendering of `/help` and `/help/Settings`.
  - Verify automatic heading `#anchor` ID generation for settings subsections.
  - Verify path traversal attempts (e.g., `/help/../../etc/passwd`) are safely blocked.
- [x] **Update `AGENTS.md`, `README.md` & `CHANGELOG`**:
  - Remove multi-language (`i18n`) references from `AGENTS.md` and update the contextual help rule to reflect same-window navigation (`/help/<Page>#<anchor>`) and mandatory per-setting documentation in `wiki/Settings.md`.
  - Document the integrated offline help in `README.md` and `CHANGELOG`.
- [x] **Run Pre-Commit Checks**: `go vet ./...`, `go test -v ./...`, `go build ./...`.

---

## Milestone 5: Automated GitHub Wiki Sync via GitHub Actions
**Goal:** Automatically publish any changes made to `./wiki/**` on the `main` branch directly to the external GitHub Wiki repository (`homelab_cert_manager.wiki.git`).

- [x] **Create `.github/workflows/sync-wiki.yml`**:
  - Trigger on `push` to `main` when paths match `wiki/**` (plus `workflow_dispatch`).
  - Set `permissions: contents: write`.
  - Checkout the main repo, clone `https://x-access-token:${{ secrets.GITHUB_TOKEN }}@github.com/${{ github.repository }}.wiki.git` into `/tmp/wiki`, sync `./wiki/` via `rsync -av --delete --exclude='.git/'`, and commit/push if changes exist.