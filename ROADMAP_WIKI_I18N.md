# Homelab Cert Manager – Roadmap: Offline Wiki & Multilanguage (DE/EN)

## Architecture & Implementation Principles
- **Simplicity & Offline-First:** All documentation and translations must be bundled locally inside the container/binary. No external runtime calls to GitHub or external CDNs.
- **Single Source of Truth for Docs:** Maintain all Wiki Markdown files in `./wiki/` inside the main repository and automatically mirror changes to the GitHub Wiki (`https://github.com/cbrosius/homelab_cert_manager.wiki.git`) via GitHub Actions.
- **Consolidated Single-Package Architecture:** All Go files and unit tests reside in `cmd/cert_manager/` (`package main`).
- **Minimal Dependency Footprint:**
  - Use `github.com/yuin/goldmark` (pure Go, zero sub-dependencies) with `goldmark.WithParserOptions(parser.WithAutoHeadingID())` to render Markdown and generate GitHub-compatible `#anchor` IDs for deep-linking.
  - Use a lightweight, standard-library JSON dictionary approach (`cmd/cert_manager/i18n.go` + `locales/en.json` & `locales/de.json`) for UI internationalization without heavy third-party i18n frameworks.

---

## Milestone 1: GitHub Wiki Synchronization & Local Content Structure
**Goal:** Pull any existing GitHub Wiki pages into `./wiki/`, ensure all core features are documented with clean headings for anchor links, and bundle them into the Docker image.

- [x] **Initialize `./wiki/` Directory**:
  - Pull existing files from `https://github.com/cbrosius/homelab_cert_manager.wiki.git` into `./wiki/` (if the remote Wiki already has content) and provide a local helper script `scripts/sync-wiki.sh` for manual pull/push if needed.
  - Ensure `.dockerignore` does **not** exclude `wiki/` or `locales/`, and update `Dockerfile` to copy `./wiki` and `./locales` into `/app/wiki` and `/app/locales` with proper permissions for `appuser`.
- [x] **Complete & Structure Wiki Pages for Deep-Linking**:
  - Inspect and complete `.md` files in `wiki/` with explicit `##` headings for `#anchor` links:
    - `Home.md`: Overview, quickstart workflow, and navigation index (`_Sidebar.md` if applicable).
    - `Root-Certificate.md`: Creating the Root CA (`#create-root-ca`) and importing/trusting it on Windows, macOS, Linux, iOS, and Android (`#trust-root-ca`).
    - `Certificates.md`: Creating service certificates (`#create-certificate`), Subject Alternative Names / SANs (`#san-configuration`), and replacing the Cert Manager's own certificate (`#self-certificate`).
    - `CSR-Signing.md`: How to generate and sign external CSRs (`#sign-csr`).
    - `Pocket-ID-OIDC.md`: Setting up Pocket ID / OIDC (`#oidc-setup`), Public Clients with PKCE (`#pkce-public-client`), automatic internal Root CA trust (`#internal-ca-trust`), and emergency local login fallback (`#emergency-fallback`).
  - Ensure any images referenced in the Wiki are stored locally inside `wiki/images/` (or `static/`) and served offline.

---

## Milestone 2: In-App Offline Wiki Viewer & Contextual Help Icons (`?`)
**Goal:** Render the `wiki/` Markdown files inside the app under `/wiki/...` (opening in a new browser tab) and place contextual `?` icons across the UI that deep-link directly to the relevant Wiki section and `#anchor`.

### 2.1 Backend – Wiki Renderer (`cmd/cert_manager/wiki.go` & `cmd/cert_manager/main.go`)
- [x] **Add `goldmark`**: Add `github.com/yuin/goldmark` with `parser.WithAutoHeadingID()` and `extension.GFM` (GitHub Flavored Markdown tables/code blocks).
- [x] **Implement `GET /wiki/` and `GET /wiki/{page}` (`cmd/cert_manager/wiki.go`)**:
  - Sanitize the requested `{page}` parameter (`filepath.Base`) to prevent path traversal; default to `Home` if empty.
  - Language-aware resolution (preparing for Milestone 3): If the active UI language is `de` and `{page}.de.md` exists in `wiki/`, render `{page}.de.md`; otherwise fall back to `{page}.md`.
  - Parse the Markdown file into HTML and rewrite internal GitHub Wiki links (e.g., `[[Page Name]]` or `[Link](Page-Name#anchor)`) so they resolve cleanly to `/wiki/Page-Name#anchor`.
  - Build a dynamic sidebar list of all available pages in `wiki/`.

### 2.2 Frontend – Wiki Layout & Admin Menu (`templates/wiki.html`)
- [x] **Create `templates/wiki.html`**:
  - Two-column Materialize layout: Sidebar navigation on the left (listing all Wiki pages + search/filter), rendered Markdown content on the right.
  - Full support for the existing **Dark Mode / Light Mode** toggle.
- [x] **Admin Menu Integration**:
  - Add a **"Wiki / Help"** menu item in the top navigation bar with `target="_blank" rel="noopener"` that opens `/wiki/Home` in a new browser tab.

### 2.3 Contextual Deep-Link Help Icons (`?`) Across the UI
- [x] Create a reusable CSS style for inline help icons (`<a href="/wiki/Page#anchor" target="_blank" rel="noopener" class="help-icon" title="..."><i class="material-icons tiny">help_outline</i></a>`).
- [x] Add contextual `?` deep-link icons to all key UI sections:
  - **Root CA Section / Modal** $\rightarrow$ `/wiki/Root-Certificate#trust-root-ca`
  - **Create Certificate Modal (especially DNS/IP SAN fields)** $\rightarrow$ `/wiki/Certificates#san-configuration`
  - **Sign CSR Modal** $\rightarrow$ `/wiki/CSR-Signing#sign-csr`
  - **Settings – Certificate Defaults** $\rightarrow$ `/wiki/Certificates#create-certificate`
  - **Settings – OIDC / Pocket ID Configuration & PKCE** $\rightarrow$ `/wiki/Pocket-ID-OIDC#oidc-setup`
  - **Login Page – OIDC / Local Fallback** $\rightarrow$ `/wiki/Pocket-ID-OIDC#emergency-fallback`

---

## Milestone 3: Multilanguage Support (DE / EN)
**Goal:** Provide a clean German and English UI (`de` / `en`) using Go's standard library and template functions, while keeping technical PKI terms clear and consistent.

### 3.1 Backend – Lightweight i18n Engine (`cmd/cert_manager/i18n.go` & `cmd/cert_manager/settings.go`)
- [x] **Create Translation Files (`locales/en.json` & `locales/de.json`)**:
  - Store flat key-value JSON dictionaries for all UI strings (navigation, buttons, table headers, modals, tooltips, settings labels, and user-facing messages).
  - Keep technical PKI terms (*Common Name (CN)*, *Subject Alternative Name (SAN)*, *CSR*, *Root CA*, *PKCE*, *OIDC Issuer URL*) intact in German labels where appropriate so admins immediately recognize them.
- [x] **Implement `cmd/cert_manager/i18n.go`**:
  - Load `locales/en.json` and `locales/de.json` on startup.
  - Provide a translation helper `T(lang, key string) string` that returns the translated string for `lang` and automatically falls back to `en` if a key is missing.
  - Register `t` in the Go HTML `template.FuncMap` so templates can call `{{ t .Lang "key_name" }}` (or `{{ call .T "key_name" }}`).
- [x] **Language Selection & Persistence (`cmd/cert_manager/settings.go`)**:
  - Add `Language string` (`"en"` or `"de"`) to `Settings` in `settings.json` (and allow optional `APP_LANGUAGE` env override).
  - If not explicitly set, auto-detect from the browser's `Accept-Language` header (`de*` $\rightarrow$ `"de"`, otherwise `"en"`) or allow switching via a language selector in the navbar/settings.

### 3.2 Frontend – Template Migration (`templates/*.html`)
- [x] Replace hardcoded English UI strings across all templates (`index.html`, `login.html`, `settings.html`, `change_password.html`, `wiki.html`) with translation keys.
- [x] Add a quick language toggle (`DE` / `EN`) in the navigation bar and in `settings.html`.

---

## Milestone 4: Tests, Documentation & Verification
- [x] **Unit Tests (`cmd/cert_manager/wiki_test.go` & `cmd/cert_manager/i18n_test.go`)**:
  - Test Wiki rendering, heading `#anchor` generation, language fallback (`Page.de.md` $\rightarrow$ `Page.md`), and path traversal protection (`../` rejection).
  - Test i18n loading, key resolution for `en` and `de`, and fallback to `en` for missing keys.
  - Verify that `locales/en.json` and `locales/de.json` contain the exact same set of keys (parity test).
- [x] **Update `README.md` & `CHANGELOG`**: Document the new Offline Wiki, contextual help icons, and DE/EN multilanguage support.
- [x] **Run Pre-Commit Checks**: `go vet ./...`, `go test -v ./...`, `go build ./...`.

---

## Milestone 5: Automated GitHub Wiki Sync via GitHub Actions
**Goal:** Automatically publish any changes made to `./wiki/**` on the `main` branch directly to the external GitHub Wiki repository (`homelab_cert_manager.wiki.git`).

- [x] **Create `.github/workflows/sync-wiki.yml`**:
  - Trigger on `push` to `main` when paths match `wiki/**` (plus `workflow_dispatch` for manual runs).
  - Set workflow permissions to `contents: write` so the default `GITHUB_TOKEN` can push to `.wiki.git`.
  - Steps:
    1. Checkout main repository (`actions/checkout@v4`).
    2. Clone `https://x-access-token:${{ secrets.GITHUB_TOKEN }}@github.com/${{ github.repository }}.wiki.git` into a temporary directory (`/tmp/wiki`).
    3. Sync files from `./wiki/` to `/tmp/wiki/` (`rsync -av --delete --exclude='.git/' ./wiki/ /tmp/wiki/`).
    4. Commit and push changes to the `.wiki.git` repository if `git status --porcelain` is non-empty (using `github-actions[bot]` as author).