package main

import (
	"html/template"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/gin-gonic/gin"
)

func TestSanitizeWikiPage(t *testing.T) {
	tests := []struct {
		input       string
		expected    string
		expectError bool
	}{
		{"", "Home", false},
		{"/", "Home", false},
		{".", "Home", false},
		{"Home", "Home", false},
		{"Home.md", "Home", false},
		{"Root-Certificate", "Root-Certificate", false},
		{"Certificates.md", "Certificates", false},
		{"../secrets", "", true},
		{"../../etc/passwd", "", true},
		{"..\\windows\\system32", "", true},
		{"sub/page", "", true},
	}

	for _, tc := range tests {
		result, err := sanitizeWikiPage(tc.input)
		if tc.expectError {
			if err == nil {
				t.Errorf("sanitizeWikiPage(%q): expected error, got nil (result: %q)", tc.input, result)
			}
		} else {
			if err != nil {
				t.Errorf("sanitizeWikiPage(%q): unexpected error: %v", tc.input, err)
			}
			if result != tc.expected {
				t.Errorf("sanitizeWikiPage(%q): expected %q, got %q", tc.input, tc.expected, result)
			}
		}
	}
}

func TestWikiMarkdownRenderingAndAnchors(t *testing.T) {
	inputMarkdown := `# Documentation Title

Welcome to the documentation.

## Trust Root CA

Instructions on trusting the Root CA.

## SAN Configuration

Details about Subject Alternative Names.

## Sign CSR

How to sign external CSRs.

## OIDC Setup

Setting up Pocket ID.

Link test: [[Root-Certificate#trust-root-ca|Root CA Guide]]
Relative link: [SANs](Certificates#san-configuration)
Screenshot link: ![Dashboard](https://raw.githubusercontent.com/cbrosius/homelab_cert_manager/main/static/screenshots/10_dashboard_with_certificates_dark.png)
`

	htmlOutput, err := renderMarkdownToHTML(inputMarkdown)
	if err != nil {
		t.Fatalf("renderMarkdownToHTML failed: %v", err)
	}

	rendered := string(htmlOutput)

	// Verify header anchor ID generation
	expectedAnchors := []string{
		`id="trust-root-ca"`,
		`id="san-configuration"`,
		`id="sign-csr"`,
		`id="oidc-setup"`,
	}

	for _, anchor := range expectedAnchors {
		if !strings.Contains(rendered, anchor) {
			t.Errorf("Expected rendered HTML to contain anchor %q, but was not found:\n%s", anchor, rendered)
		}
	}

	// Verify link rewrites
	if !strings.Contains(rendered, `href="/wiki/Root-Certificate#trust-root-ca"`) {
		t.Errorf("Expected wiki pipe link to be rewritten to /wiki/Root-Certificate#trust-root-ca, got:\n%s", rendered)
	}

	if !strings.Contains(rendered, `href="/wiki/Certificates#san-configuration"`) {
		t.Errorf("Expected relative markdown link to be rewritten to /wiki/Certificates#san-configuration, got:\n%s", rendered)
	}

	// Verify raw github screenshot link rewrite to local static path
	if !strings.Contains(rendered, `src="/static/screenshots/10_dashboard_with_certificates_dark.png"`) {
		t.Errorf("Expected screenshot link to be rewritten to /static/screenshots/..., got:\n%s", rendered)
	}
}

func TestResolveWikiFile_LanguageFallback(t *testing.T) {
	tempWikiDir := t.TempDir()

	// Create test markdown files
	if err := os.WriteFile(filepath.Join(tempWikiDir, "TestPage.md"), []byte("# Test Page\nEnglish content"), 0644); err != nil {
		t.Fatalf("Failed to create TestPage.md: %v", err)
	}
	if err := os.WriteFile(filepath.Join(tempWikiDir, "LocalizedPage.md"), []byte("# Localized Page\nEnglish content"), 0644); err != nil {
		t.Fatalf("Failed to create LocalizedPage.md: %v", err)
	}
	if err := os.WriteFile(filepath.Join(tempWikiDir, "LocalizedPage.de.md"), []byte("# Lokalisierte Seite\nDeutscher Inhalt"), 0644); err != nil {
		t.Fatalf("Failed to create LocalizedPage.de.md: %v", err)
	}

	// 1. Request LocalizedPage with lang="de" -> should resolve to .de.md
	fileDe, slugDe := resolveWikiFile(tempWikiDir, "LocalizedPage", "de")
	if !strings.HasSuffix(fileDe, "LocalizedPage.de.md") {
		t.Errorf("Expected LocalizedPage with lang=de to resolve to .de.md, got %q", fileDe)
	}
	if slugDe != "LocalizedPage" {
		t.Errorf("Expected slug 'LocalizedPage', got %q", slugDe)
	}

	// 2. Request LocalizedPage with lang="en" -> should resolve to .md
	fileEn, _ := resolveWikiFile(tempWikiDir, "LocalizedPage", "en")
	if !strings.HasSuffix(fileEn, "LocalizedPage.md") {
		t.Errorf("Expected LocalizedPage with lang=en to resolve to .md, got %q", fileEn)
	}

	// 3. Request TestPage with lang="de" (no de file exists) -> fallback to .md
	fileFallback, _ := resolveWikiFile(tempWikiDir, "TestPage", "de")
	if !strings.HasSuffix(fileFallback, "TestPage.md") {
		t.Errorf("Expected TestPage with lang=de to fall back to .md, got %q", fileFallback)
	}
}

func TestWikiHTTPHandler_PathTraversalRejection(t *testing.T) {
	gin.SetMode(gin.TestMode)
	r := gin.New()

	r.SetFuncMap(template.FuncMap{
		"toJson": toJson,
		"t": func(lang, key string) string {
			return T(lang, key)
		},
	})
	pattern := "templates/*"
	if _, err := os.Stat("templates"); os.IsNotExist(err) {
		pattern = "../../templates/*"
	}
	r.LoadHTMLGlob(pattern)

	r.GET("/wiki", handleWikiPage)
	r.GET("/wiki/:page", handleWikiPage)

	// 1. Path traversal attempt with "../secret"
	req, _ := http.NewRequest("GET", "/wiki/..%2f..%2fsecret", nil)
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	if w.Code != http.StatusBadRequest && w.Code != http.StatusNotFound {
		t.Errorf("Expected path traversal request to be rejected with 400 or 404, got %d", w.Code)
	}

	// 2. Valid request to Home
	reqHome, _ := http.NewRequest("GET", "/wiki/Home", nil)
	wHome := httptest.NewRecorder()
	r.ServeHTTP(wHome, reqHome)

	if wHome.Code != http.StatusOK {
		t.Errorf("Expected valid wiki page /wiki/Home to return 200, got %d", wHome.Code)
	}
}
