package main

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"

	"github.com/gin-gonic/gin"
)

func TestI18n_LoadingAndResolution(t *testing.T) {
	// Initialize i18n
	if err := initI18n(); err != nil {
		t.Fatalf("initI18n failed: %v", err)
	}

	// 1. Existing key in English
	valEn := T("en", "brand_name")
	if valEn != "HomeLab CA" {
		t.Errorf("Expected T('en', 'brand_name') to be 'HomeLab CA', got %q", valEn)
	}

	// 2. Existing key in German
	valDe := T("de", "nav_settings")
	if valDe != "Einstellungen" {
		t.Errorf("Expected T('de', 'nav_settings') to be 'Einstellungen', got %q", valDe)
	}

	// 3. Fallback to English for key missing in German
	i18nMu.Lock()
	translations["en"]["test_fallback_key"] = "English Fallback Value"
	delete(translations["de"], "test_fallback_key")
	i18nMu.Unlock()

	valFallback := T("de", "test_fallback_key")
	if valFallback != "English Fallback Value" {
		t.Errorf("Expected fallback to English for missing German key, got %q", valFallback)
	}

	// 4. Missing in both returns the key itself
	valMissing := T("de", "non_existent_key_12345")
	if valMissing != "non_existent_key_12345" {
		t.Errorf("Expected missing key to return the key itself, got %q", valMissing)
	}
}

func TestI18n_LanguageParity(t *testing.T) {
	localesDir := getLocalesDir()

	enData, err := os.ReadFile(filepath.Join(localesDir, "en.json"))
	if err != nil {
		t.Fatalf("Failed to read locales/en.json: %v", err)
	}

	deData, err := os.ReadFile(filepath.Join(localesDir, "de.json"))
	if err != nil {
		t.Fatalf("Failed to read locales/de.json: %v", err)
	}

	var enMap map[string]string
	if err := json.Unmarshal(enData, &enMap); err != nil {
		t.Fatalf("Failed to parse locales/en.json: %v", err)
	}

	var deMap map[string]string
	if err := json.Unmarshal(deData, &deMap); err != nil {
		t.Fatalf("Failed to parse locales/de.json: %v", err)
	}

	// Check keys in en that are missing in de
	for k := range enMap {
		if _, exists := deMap[k]; !exists {
			t.Errorf("Key parity error: Key %q present in en.json but missing in de.json", k)
		}
	}

	// Check keys in de that are missing in en
	for k := range deMap {
		if _, exists := enMap[k]; !exists {
			t.Errorf("Key parity error: Key %q present in de.json but missing in en.json", k)
		}
	}

	if len(enMap) != len(deMap) {
		t.Errorf("Key count mismatch: en.json has %d keys, but de.json has %d keys", len(enMap), len(deMap))
	}
}

func TestI18n_GetRequestLanguage(t *testing.T) {
	gin.SetMode(gin.TestMode)

	// 1. Query parameter (?lang=de)
	req1, _ := http.NewRequest("GET", "/test?lang=de", nil)
	c1, _ := gin.CreateTestContext(httptest.NewRecorder())
	c1.Request = req1
	if lang := getRequestLanguage(c1); lang != "de" {
		t.Errorf("Expected query param lang=de to resolve to 'de', got %q", lang)
	}

	// 2. Cookie override
	req2, _ := http.NewRequest("GET", "/test", nil)
	req2.AddCookie(&http.Cookie{Name: "app_lang", Value: "de"})
	c2, _ := gin.CreateTestContext(httptest.NewRecorder())
	c2.Request = req2
	if lang := getRequestLanguage(c2); lang != "de" {
		t.Errorf("Expected cookie app_lang=de to resolve to 'de', got %q", lang)
	}

	// 3. Accept-Language header (German browser)
	req3, _ := http.NewRequest("GET", "/test", nil)
	req3.Header.Set("Accept-Language", "de-DE,de;q=0.9,en;q=0.8")
	c3, _ := gin.CreateTestContext(httptest.NewRecorder())
	c3.Request = req3
	if lang := getRequestLanguage(c3); lang != "de" {
		t.Errorf("Expected Accept-Language header de-DE to resolve to 'de', got %q", lang)
	}

	// 4. Accept-Language header (English / Other browser)
	req4, _ := http.NewRequest("GET", "/test", nil)
	req4.Header.Set("Accept-Language", "fr-FR,fr;q=0.9,en-US;q=0.8,en;q=0.7")
	c4, _ := gin.CreateTestContext(httptest.NewRecorder())
	c4.Request = req4
	if lang := getRequestLanguage(c4); lang != "en" {
		t.Errorf("Expected non-German browser to resolve to 'en', got %q", lang)
	}
}
