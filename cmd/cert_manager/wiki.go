package main

import (
	"bytes"
	"fmt"
	"html/template"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"

	"github.com/gin-gonic/gin"
	"github.com/spf13/viper"
	"github.com/yuin/goldmark"
	"github.com/yuin/goldmark/extension"
	"github.com/yuin/goldmark/parser"
	goldmarkHtml "github.com/yuin/goldmark/renderer/html"
)

var wikiMarkdownParser = goldmark.New(
	goldmark.WithExtensions(
		extension.GFM,
	),
	goldmark.WithParserOptions(
		parser.WithAutoHeadingID(),
	),
	goldmark.WithRendererOptions(
		goldmarkHtml.WithUnsafe(),
	),
)

// WikiPageItem represents a page entry in the sidebar.
type WikiPageItem struct {
	Slug     string
	Title    string
	IsActive bool
}

// wikiDir returns the path to the wiki markdown files directory.
func getWikiDir() string {
	if dir := os.Getenv("WIKI_DIR"); dir != "" {
		return dir
	}
	// Check local directory
	if info, err := os.Stat("wiki"); err == nil && info.IsDir() {
		return "wiki"
	}
	if info, err := os.Stat("/app/wiki"); err == nil && info.IsDir() {
		return "/app/wiki"
	}
	return "wiki"
}

// sanitizeWikiPage sanitizes the requested wiki page name to prevent path traversal attacks.
func sanitizeWikiPage(rawPage string) (string, error) {
	trimmed := strings.TrimSpace(rawPage)
	if trimmed == "" || trimmed == "/" || trimmed == "." {
		return "Home", nil
	}

	// Reject directory traversal attempts explicitly
	if strings.Contains(trimmed, "..") || strings.Contains(trimmed, "/") || strings.Contains(trimmed, "\\") {
		return "", fmt.Errorf("invalid page name: path traversal rejected")
	}

	base := filepath.Base(trimmed)
	if base == "." || base == ".." || base == "" {
		return "Home", nil
	}

	clean := strings.TrimSuffix(base, ".md")
	if clean == "" {
		return "Home", nil
	}

	return clean, nil
}

// rewriteWikiLinks rewrites wiki links, images, and raw GitHub URLs.
func rewriteWikiLinks(input string) string {
	// 1. Rewrite [[Target|Label]] -> [Label](/wiki/Target)
	wikiLinkWithPipeRegex := regexp.MustCompile(`\[\[([^|\]]+)\|([^\]]+)\]\]`)
	output := wikiLinkWithPipeRegex.ReplaceAllString(input, `[$2](/wiki/$1)`)

	// 2. Rewrite [[Target]] -> [Target](/wiki/Target)
	wikiLinkSimpleRegex := regexp.MustCompile(`\[\[([^\]]+)\]\]`)
	output = wikiLinkSimpleRegex.ReplaceAllStringFunc(output, func(m string) string {
		match := wikiLinkSimpleRegex.FindStringSubmatch(m)
		if len(match) > 1 {
			target := strings.TrimSpace(match[1])
			slug := strings.ReplaceAll(target, " ", "-")
			return fmt.Sprintf("[%s](/wiki/%s)", target, slug)
		}
		return m
	})

	// 3. Rewrite relative markdown links [Label](Target) where Target is not external or anchor
	mdLinkRegex := regexp.MustCompile(`\[([^\]]+)\]\(([^)]+)\)`)
	output = mdLinkRegex.ReplaceAllStringFunc(output, func(m string) string {
		match := mdLinkRegex.FindStringSubmatch(m)
		if len(match) > 2 {
			label := match[1]
			target := strings.TrimSpace(match[2])

			// Rewrite GitHub raw screenshots to local static path
			target = strings.ReplaceAll(target, "https://raw.githubusercontent.com/cbrosius/homelab_cert_manager/main/static/screenshots/", "/static/screenshots/")

			// Skip external links, anchors, mailto, or absolute paths
			if strings.HasPrefix(target, "http://") || strings.HasPrefix(target, "https://") ||
				strings.HasPrefix(target, "mailto:") || strings.HasPrefix(target, "#") ||
				strings.HasPrefix(target, "/") {
				return fmt.Sprintf("[%s](%s)", label, target)
			}

			// Split target into path and anchor (e.g. Page#anchor or Page.md#anchor)
			parts := strings.SplitN(target, "#", 2)
			pageName := strings.TrimSuffix(parts[0], ".md")
			anchor := ""
			if len(parts) == 2 {
				anchor = "#" + parts[1]
			}

			// If target was just a file or page name
			if pageName == "" && anchor != "" {
				return fmt.Sprintf("[%s](%s)", label, anchor)
			}
			return fmt.Sprintf("[%s](/wiki/%s%s)", label, pageName, anchor)
		}
		return m
	})

	// 4. Rewrite markdown image links pointing to remote repo screenshots to local static path
	output = strings.ReplaceAll(output, "https://raw.githubusercontent.com/cbrosius/homelab_cert_manager/main/static/screenshots/", "/static/screenshots/")

	return output
}

// resolveWikiFile finds the appropriate markdown file considering language preference.
func resolveWikiFile(wikiDir, pageSlug, lang string) (string, string) {
	// If lang is German, check if {pageSlug}.de.md exists
	if strings.HasPrefix(strings.ToLower(lang), "de") {
		deFile := filepath.Join(wikiDir, pageSlug+".de.md")
		if info, err := os.Stat(deFile); err == nil && !info.IsDir() {
			return deFile, pageSlug
		}
	}

	// Direct match {pageSlug}.md
	directFile := filepath.Join(wikiDir, pageSlug+".md")
	if info, err := os.Stat(directFile); err == nil && !info.IsDir() {
		return directFile, pageSlug
	}

	// Case-insensitive fallback
	entries, err := os.ReadDir(wikiDir)
	if err == nil {
		lowerSlug := strings.ToLower(pageSlug)
		for _, e := range entries {
			if e.IsDir() {
				continue
			}
			name := e.Name()
			if strings.HasSuffix(strings.ToLower(name), ".md") {
				base := strings.TrimSuffix(name, filepath.Ext(name))
				if strings.ToLower(base) == lowerSlug {
					return filepath.Join(wikiDir, name), base
				}
			}
		}
	}

	return "", pageSlug
}

// extractWikiTitle extracts the first H1 header (# Title) from markdown, or formats slug.
func extractWikiTitle(filePath, slug string) string {
	content, err := os.ReadFile(filePath)
	if err == nil {
		lines := strings.Split(string(content), "\n")
		for _, line := range lines {
			trimmed := strings.TrimSpace(line)
			if strings.HasPrefix(trimmed, "# ") {
				title := strings.TrimSpace(strings.TrimPrefix(trimmed, "# "))
				if title != "" {
					return title
				}
			}
		}
	}

	// Fallback to formatted slug
	words := strings.Split(slug, "-")
	for i, w := range words {
		if len(w) > 0 {
			words[i] = strings.ToUpper(w[:1]) + w[1:]
		}
	}
	return strings.Join(words, " ")
}

// listWikiPages scans the wiki directory for all available documentation pages.
func listWikiPages(wikiDir, activeSlug string) []WikiPageItem {
	var pages []WikiPageItem
	entries, err := os.ReadDir(wikiDir)
	if err != nil {
		return pages
	}

	seen := make(map[string]bool)

	for _, e := range entries {
		if e.IsDir() {
			continue
		}
		name := e.Name()
		if !strings.HasSuffix(strings.ToLower(name), ".md") {
			continue
		}
		// Exclude internal wiki partials and language suffixes for sidebar listing
		if strings.HasPrefix(name, "_") || strings.HasSuffix(name, ".de.md") {
			continue
		}

		slug := strings.TrimSuffix(name, filepath.Ext(name))
		if seen[slug] {
			continue
		}
		seen[slug] = true

		fullPath := filepath.Join(wikiDir, name)
		title := extractWikiTitle(fullPath, slug)

		pages = append(pages, WikiPageItem{
			Slug:     slug,
			Title:    title,
			IsActive: strings.EqualFold(slug, activeSlug),
		})
	}

	// Sort pages: "Home" first, then predefined order or alphabetical
	preferredOrder := map[string]int{
		"Home":                       1,
		"Installation-and-Deployment": 2,
		"Root-Certificate":           3,
		"Root-CA-and-Client-Trust":   4,
		"Certificates":               5,
		"Configuration":              6,
		"CSR-Signing":                7,
		"Pocket-ID-OIDC":             8,
		"OIDC-and-Pocket-ID":         9,
		"Security":                   10,
		"FAQ":                        11,
	}

	sort.Slice(pages, func(i, j int) bool {
		orderI, okI := preferredOrder[pages[i].Slug]
		if !okI {
			orderI = 100
		}
		orderJ, okJ := preferredOrder[pages[j].Slug]
		if !okJ {
			orderJ = 100
		}
		if orderI != orderJ {
			return orderI < orderJ
		}
		return pages[i].Title < pages[j].Title
	})

	return pages
}

// renderMarkdownToHTML parses markdown content and renders it to safe HTML.
func renderMarkdownToHTML(markdown string) (template.HTML, error) {
	rewritten := rewriteWikiLinks(markdown)
	var buf bytes.Buffer
	if err := wikiMarkdownParser.Convert([]byte(rewritten), &buf); err != nil {
		return "", err
	}
	return template.HTML(buf.String()), nil
}

// handleWikiPage serves the in-app offline wiki viewer.
func handleWikiPage(c *gin.Context) {
	rawPage := c.Param("page")
	slug, err := sanitizeWikiPage(rawPage)
	if err != nil {
		c.String(http.StatusBadRequest, "Invalid page name: path traversal rejected")
		return
	}

	wikiDir := getWikiDir()
	lang := getRequestLanguage(c)

	filePath, resolvedSlug := resolveWikiFile(wikiDir, slug, lang)
	pages := listWikiPages(wikiDir, resolvedSlug)

	var renderedContent template.HTML
	var pageTitle string

	if filePath == "" {
		pageTitle = "Page Not Found - " + slug
		renderedContent = template.HTML(fmt.Sprintf(`
			<div class="wiki-not-found">
				<h3><i class="material-icons" style="font-size: 32px; vertical-align: middle; color: var(--accent-warning);">search_off</i> Page Not Found</h3>
				<p>The requested documentation page <code>%s</code> could not be found.</p>
				<p><a href="/wiki/Home" class="btn-primary" style="display: inline-flex; align-items: center; gap: 0.5rem; margin-top: 1rem;">
					<i class="material-icons">home</i> Return to Wiki Home
				</a></p>
			</div>
		`, template.HTMLEscapeString(slug)))
	} else {
		contentBytes, err := os.ReadFile(filePath)
		if err != nil {
			c.String(http.StatusInternalServerError, "Error reading wiki page")
			return
		}
		pageTitle = extractWikiTitle(filePath, resolvedSlug)
		html, err := renderMarkdownToHTML(string(contentBytes))
		if err != nil {
			c.String(http.StatusInternalServerError, "Error rendering markdown")
			return
		}
		renderedContent = html
	}

	c.HTML(http.StatusOK, "wiki.html", gin.H{
		"Title":           pageTitle,
		"CurrentSlug":     resolvedSlug,
		"Content":         renderedContent,
		"Pages":           pages,
		"Lang":            lang,
		"defaultPassword": checkPasswordHash("admin", viper.GetString("password")),
		"csrfToken":       getCSRFToken(c.Request),
	})
}
