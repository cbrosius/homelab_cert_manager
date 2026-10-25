package main

import (
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"

	"github.com/gin-gonic/gin"
)

var (
	i18nMu           sync.RWMutex
	translations     = make(map[string]map[string]string)
	supportedLocales = []string{"en", "de"}
)

// getLocalesDir returns the path to the locales directory.
func getLocalesDir() string {
	if dir := os.Getenv("LOCALES_DIR"); dir != "" {
		return dir
	}
	if info, err := os.Stat("locales"); err == nil && info.IsDir() {
		return "locales"
	}
	if info, err := os.Stat("/app/locales"); err == nil && info.IsDir() {
		return "/app/locales"
	}
	return "locales"
}

// initI18n loads translations from locales directory.
func initI18n() error {
	i18nMu.Lock()
	defer i18nMu.Unlock()

	localesDir := getLocalesDir()
	for _, lang := range supportedLocales {
		filePath := filepath.Join(localesDir, lang+".json")
		data, err := os.ReadFile(filePath)
		if err != nil {
			log.Printf("Warning: Failed to load locale %s from %s: %v", lang, filePath, err)
			continue
		}

		var dict map[string]string
		if err := json.Unmarshal(data, &dict); err != nil {
			return fmt.Errorf("failed to parse locale %s: %w", lang, err)
		}

		translations[lang] = dict
	}

	return nil
}

// normalizeLanguage normalizes language codes to "en" or "de".
func normalizeLanguage(lang string) string {
	trimmed := strings.ToLower(strings.TrimSpace(lang))
	if strings.HasPrefix(trimmed, "de") {
		return "de"
	}
	if strings.HasPrefix(trimmed, "en") {
		return "en"
	}
	return "en"
}

// T translates a key into the specified language with fallback to English.
func T(lang, key string) string {
	i18nMu.RLock()
	defer i18nMu.RUnlock()

	normalizedLang := normalizeLanguage(lang)

	// Try requested language
	if dict, exists := translations[normalizedLang]; exists {
		if val, found := dict[key]; found && val != "" {
			return val
		}
	}

	// Fallback to English
	if normalizedLang != "en" {
		if dict, exists := translations["en"]; exists {
			if val, found := dict[key]; found && val != "" {
				return val
			}
		}
	}

	return key
}

// getRequestLanguage determines the language for the current request.
func getRequestLanguage(c *gin.Context) string {
	if c == nil || c.Request == nil {
		return getAppLanguage()
	}

	// 1. Query parameter override (?lang=de)
	if qLang := c.Query("lang"); qLang != "" {
		return normalizeLanguage(qLang)
	}

	// 2. Cookie preference
	if cookie, err := c.Cookie("app_lang"); err == nil && cookie != "" {
		return normalizeLanguage(cookie)
	}

	// 3. Application settings or environment variable
	if configured := getAppLanguage(); configured != "" {
		return configured
	}

	// 4. Accept-Language header
	acceptHeader := c.GetHeader("Accept-Language")
	if acceptHeader != "" {
		parts := strings.Split(acceptHeader, ",")
		for _, part := range parts {
			tag := strings.TrimSpace(strings.Split(part, ";")[0])
			if strings.HasPrefix(strings.ToLower(tag), "de") {
				return "de"
			}
			if strings.HasPrefix(strings.ToLower(tag), "en") {
				return "en"
			}
		}
	}

	return "en"
}

// handleSetLanguage handles switching UI language via GET /set-language/:lang or POST /settings/language
func handleSetLanguage(c *gin.Context) {
	lang := c.Param("lang")
	if lang == "" {
		lang = c.PostForm("language")
	}
	normalized := normalizeLanguage(lang)

	// Set cookie (1 year duration)
	isSecure := c.Request.TLS != nil || c.GetHeader("X-Forwarded-Proto") == "https"
	c.SetCookie("app_lang", normalized, 365*24*3600, "/", "", isSecure, false)

	// If authenticated, persist to settings.json
	session, err := store.Get(c.Request, "session-name")
	if err == nil && session.Values["authenticated"] == true {
		_ = saveLanguageSetting(normalized)
	}

	redirectURL := c.Query("redirect")
	if redirectURL == "" {
		redirectURL = c.GetHeader("Referer")
	}
	if redirectURL == "" || strings.Contains(redirectURL, "/set-language") {
		redirectURL = "/certificates"
	}

	c.Redirect(http.StatusSeeOther, redirectURL)
}
