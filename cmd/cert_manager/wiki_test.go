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

func TestSanitizeWikiSlug(t *testing.T) {
	tests := []struct {
		input    string
		expected string
	}{
		{"Home", "Home"},
		{"Settings.md", "Settings"},
		{"Root-Certificate", "Root-Certificate"},
		{"../../etc/passwd", "passwd"},
		{"..\\..\\windows\\system32", "system32"},
		{"Invalid*Chars!?", "InvalidChars"},
		{"", "Home"},
		{"   ", "Home"},
	}

	for _, tc := range tests {
		got := sanitizeWikiSlug(tc.input)
		if got != tc.expected {
			t.Errorf("sanitizeWikiSlug(%q) = %q; expected %q", tc.input, got, tc.expected)
		}
	}
}

func TestRewriteWikiLinks(t *testing.T) {
	input := `
# Overview
See [Settings](Settings#oidc-enabled) for more information.
Check [Root Certificate](Root-Certificate) to trust the CA.
External link: [GitHub](https://github.com/cbrosius/homelab_cert_manager).
In-page jump: [Jump](#section).
Wiki syntax: [[Settings#country|Country Setting]] or [[Certificates]].
`
	result := rewriteWikiLinks(input)

	if !strings.Contains(result, "[Settings](/help/Settings#oidc-enabled)") {
		t.Errorf("Expected rewritten settings link, got: %s", result)
	}
	if !strings.Contains(result, "[Root Certificate](/help/Root-Certificate)") {
		t.Errorf("Expected rewritten root cert link, got: %s", result)
	}
	if !strings.Contains(result, "[GitHub](https://github.com/cbrosius/homelab_cert_manager)") {
		t.Errorf("Expected external link to remain unchanged, got: %s", result)
	}
	if !strings.Contains(result, "[Jump](#section)") {
		t.Errorf("Expected in-page anchor to remain unchanged, got: %s", result)
	}
	if !strings.Contains(result, "[Country Setting](/help/Settings#country)") {
		t.Errorf("Expected wiki syntax with anchor to be rewritten, got: %s", result)
	}
	if !strings.Contains(result, "[Certificates](/help/Certificates)") {
		t.Errorf("Expected plain wiki syntax to be rewritten, got: %s", result)
	}
}

func TestRenderWikiContent_AutoHeadingID(t *testing.T) {
	markdown := `
### Country
Details about country.

### OIDC Enabled
Details about OIDC.

<a id="custom-anchor"></a>
### Section with Anchor
More info.
`
	html, err := renderWikiContent(markdown)
	if err != nil {
		t.Fatalf("renderWikiContent failed: %v", err)
	}

	htmlStr := string(html)
	if !strings.Contains(htmlStr, `id="country"`) {
		t.Errorf("Expected auto heading id='country', got: %s", htmlStr)
	}
	if !strings.Contains(htmlStr, `id="oidc-enabled"`) {
		t.Errorf("Expected auto heading id='oidc-enabled', got: %s", htmlStr)
	}
	if !strings.Contains(htmlStr, `id="custom-anchor"`) {
		t.Errorf("Expected preserved custom HTML anchor id='custom-anchor', got: %s", htmlStr)
	}
}

func TestShowHelpPage_HTTP(t *testing.T) {
	gin.SetMode(gin.TestMode)

	// Create temporary wiki directory for test isolation
	tempWiki := t.TempDir()
	os.Setenv("WIKI_DIR", tempWiki)
	defer os.Unsetenv("WIKI_DIR")

	homeContent := "# HomeLab Cert Manager Help\n\nWelcome to help."
	if err := os.WriteFile(filepath.Join(tempWiki, "Home.md"), []byte(homeContent), 0644); err != nil {
		t.Fatalf("Failed to create mock Home.md: %v", err)
	}

	settingsContent := "# Settings Reference\n\n### Country\nCountry setting details."
	if err := os.WriteFile(filepath.Join(tempWiki, "Settings.md"), []byte(settingsContent), 0644); err != nil {
		t.Fatalf("Failed to create mock Settings.md: %v", err)
	}

	router := gin.New()
	// Mock HTML template rendering for test
	router.SetHTMLTemplate(template.Must(template.New("help.html").Parse(`
		<html>
			<head><title>{{ .pageTitle }}</title></head>
			<body>
				<h1>{{ .pageTitle }}</h1>
				<div class="content">{{ .content }}</div>
			</body>
		</html>
	`)))

	router.GET("/help", showHelpPage)
	router.GET("/help/:page", showHelpPage)

	// 1. Test GET /help (defaults to Home)
	req := httptest.NewRequest("GET", "/help", nil)
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("GET /help returned status %d; expected %d", w.Code, http.StatusOK)
	}
	if !strings.Contains(w.Body.String(), "HomeLab Cert Manager Help") {
		t.Errorf("GET /help body does not contain expected title, got: %s", w.Body.String())
	}

	// 2. Test GET /help/Settings
	req = httptest.NewRequest("GET", "/help/Settings", nil)
	w = httptest.NewRecorder()
	router.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("GET /help/Settings returned status %d; expected %d", w.Code, http.StatusOK)
	}
	if !strings.Contains(w.Body.String(), "Settings Reference") {
		t.Errorf("GET /help/Settings body does not contain expected title, got: %s", w.Body.String())
	}
	if !strings.Contains(w.Body.String(), `id="country"`) {
		t.Errorf("GET /help/Settings body does not contain auto-heading ID 'country', got: %s", w.Body.String())
	}

	// 3. Test non-existent page redirect to /help/Home
	req = httptest.NewRequest("GET", "/help/NonExistent", nil)
	w = httptest.NewRecorder()
	router.ServeHTTP(w, req)

	if w.Code != http.StatusSeeOther {
		t.Errorf("GET /help/NonExistent returned status %d; expected redirect %d", w.Code, http.StatusSeeOther)
	}
	if w.Header().Get("Location") != "/help/Home" {
		t.Errorf("Expected redirect to /help/Home, got %q", w.Header().Get("Location"))
	}

	// 4. Test path traversal safety (must be blocked by router 404 or redirect 303, never 200 OK)
	req = httptest.NewRequest("GET", "/help/..%2F..%2Fetc%2Fpasswd", nil)
	w = httptest.NewRecorder()
	router.ServeHTTP(w, req)

	if w.Code == http.StatusOK {
		t.Errorf("Path traversal request unexpectedly returned 200 OK")
	}
	if w.Code != http.StatusNotFound && w.Code != http.StatusSeeOther {
		t.Errorf("Path traversal request returned status %d; expected 404 or 303", w.Code)
	}
}
