package main

import (
	"bytes"
	"fmt"
	"html/template"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/gin-gonic/gin"
	"github.com/yuin/goldmark"
	"github.com/yuin/goldmark/extension"
	"github.com/yuin/goldmark/parser"
	"github.com/yuin/goldmark/renderer/html"
)

// WikiPageMeta represents metadata for a documentation page.
type WikiPageMeta struct {
	Slug     string
	Title    string
	Icon     string
	Category string
	IsActive bool
}

// goldmark instance configured with GFM, auto heading IDs, and unsafe HTML (to support custom anchor tags).
var wikiGoldmark = goldmark.New(
	goldmark.WithExtensions(extension.GFM),
	goldmark.WithParserOptions(
		parser.WithAutoHeadingID(),
	),
	goldmark.WithRendererOptions(
		html.WithUnsafe(),
	),
)

// wikiDir returns the path to the wiki documentation directory.
func getWikiDir() string {
	if dir := os.Getenv("WIKI_DIR"); dir != "" {
		return dir
	}
	return "wiki"
}

// pageIconMap assigns meaningful Material Icons to standard documentation pages.
var pageIconMap = map[string]string{
	"home":                         "home",
	"root-certificate":             "security",
	"root-ca-and-client-trust":     "verified_user",
	"certificates":                 "card_membership",
	"csr-signing":                  "assignment_turned_in",
	"settings":                     "tune",
	"configuration":                "settings",
	"oidc-and-pocket-id":           "fingerprint",
	"installation-and-deployment":  "cloud_download",
	"security":                     "shield",
	"faq":                          "help_center",
}

// pageOrder defines preferred ordering for standard pages.
var pageOrder = map[string]int{
	"home":                         1,
	"root-certificate":             2,
	"root-ca-and-client-trust":     3,
	"certificates":                 4,
	"csr-signing":                  5,
	"settings":                     6,
	"configuration":                7,
	"oidc-and-pocket-id":           8,
	"installation-and-deployment":  9,
	"security":                     10,
	"faq":                          11,
}

// sanitizeWikiSlug ensures the page slug contains only valid characters and prevents path traversal.
func sanitizeWikiSlug(page string) string {
	page = strings.TrimSpace(page)
	if page == "" {
		return "Home"
	}
	// Strip directory paths to prevent path traversal
	clean := filepath.Base(page)
	// Remove trailing .md if provided
	clean = strings.TrimSuffix(clean, ".md")
	// Allow alphanumeric, dashes, and underscores
	reg := regexp.MustCompile(`[^a-zA-Z0-9_\-]`)
	clean = reg.ReplaceAllString(clean, "")
	if clean == "" {
		return "Home"
	}
	return clean
}

// getWikiPages returns a sorted list of available wiki pages with extracted titles and icons.
func getWikiPages(wikiDir, activeSlug string) ([]WikiPageMeta, error) {
	entries, err := os.ReadDir(wikiDir)
	if err != nil {
		return nil, fmt.Errorf("unable to read wiki directory: %w", err)
	}

	var pages []WikiPageMeta
	for _, entry := range entries {
		if entry.IsDir() {
			continue
		}
		name := entry.Name()
		if !strings.HasSuffix(strings.ToLower(name), ".md") {
			continue
		}
		// Ignore hidden files and GitHub Wiki special files
		if strings.HasPrefix(name, "_") || strings.HasPrefix(name, ".") {
			continue
		}

		slug := strings.TrimSuffix(name, filepath.Ext(name))
		filePath := filepath.Join(wikiDir, name)
		title := extractTitleFromMarkdown(filePath, slug)

		lowerSlug := strings.ToLower(slug)
		icon := pageIconMap[lowerSlug]
		if icon == "" {
			icon = "article"
		}

		category := "Guides"
		if lowerSlug == "home" {
			category = "Overview"
		} else if lowerSlug == "settings" || lowerSlug == "configuration" {
			category = "Reference"
		} else if lowerSlug == "faq" {
			category = "Support"
		}

		isActive := strings.EqualFold(slug, activeSlug)

		pages = append(pages, WikiPageMeta{
			Slug:     slug,
			Title:    title,
			Icon:     icon,
			Category: category,
			IsActive: isActive,
		})
	}

	// Sort pages by predefined order or alphabetically
	for i := 0; i < len(pages)-1; i++ {
		for j := i + 1; j < len(pages); j++ {
			orderI := pageOrder[strings.ToLower(pages[i].Slug)]
			if orderI == 0 {
				orderI = 100
			}
			orderJ := pageOrder[strings.ToLower(pages[j].Slug)]
			if orderJ == 0 {
				orderJ = 100
			}

			if orderI > orderJ || (orderI == orderJ && pages[i].Title > pages[j].Title) {
				pages[i], pages[j] = pages[j], pages[i]
			}
		}
	}

	return pages, nil
}

// extractTitleFromMarkdown reads the first `# Heading` from the markdown file, or humanizes the slug.
func extractTitleFromMarkdown(filePath, slug string) string {
	content, err := os.ReadFile(filePath)
	if err != nil {
		return humanizeSlug(slug)
	}

	lines := strings.Split(string(content), "\n")
	for _, line := range lines {
		trimmed := strings.TrimSpace(line)
		if strings.HasPrefix(trimmed, "# ") {
			title := strings.TrimPrefix(trimmed, "# ")
			return strings.TrimSpace(title)
		}
	}

	return humanizeSlug(slug)
}

// humanizeSlug converts "Root-Certificate" to "Root Certificate".
func humanizeSlug(slug string) string {
	s := strings.ReplaceAll(slug, "-", " ")
	s = strings.ReplaceAll(s, "_", " ")
	return strings.Title(s)
}

// findWikiFile resolves the target markdown file path, supporting case-insensitive lookups on case-sensitive OS.
func findWikiFile(wikiDir, slug string) (string, string, bool) {
	exactPath := filepath.Join(wikiDir, slug+".md")
	if _, err := os.Stat(exactPath); err == nil {
		return exactPath, slug, true
	}

	// Fallback to case-insensitive match
	entries, err := os.ReadDir(wikiDir)
	if err != nil {
		return "", "", false
	}

	target := strings.ToLower(slug + ".md")
	for _, entry := range entries {
		if strings.ToLower(entry.Name()) == target {
			actualSlug := strings.TrimSuffix(entry.Name(), filepath.Ext(entry.Name()))
			return filepath.Join(wikiDir, entry.Name()), actualSlug, true
		}
	}

	return "", "", false
}

var (
	// Matches standard markdown links: [text](target)
	mdLinkRegex = regexp.MustCompile(`\[([^\]]+)\]\(([^)]+)\)`)
	// Matches MediaWiki syntax: [[Page]] or [[Page|Text]] or [[Page#Anchor]]
	wikiLinkRegex = regexp.MustCompile(`\[\[([^\]|#]+)(?:#([^\]|]+))?(?:\|([^\]]+))?\]\]`)
)

// rewriteWikiLinks updates relative markdown and wiki-style links to point to /help/<Page>#<anchor>.
func rewriteWikiLinks(md string) string {
	// First rewrite [[Page#Anchor|Text]] syntax
	md = wikiLinkRegex.ReplaceAllStringFunc(md, func(match string) string {
		submatches := wikiLinkRegex.FindStringSubmatch(match)
		if len(submatches) < 4 {
			return match
		}
		page := strings.TrimSpace(submatches[1])
		anchor := strings.TrimSpace(submatches[2])
		text := strings.TrimSpace(submatches[3])
		if text == "" {
			text = page
		}
		url := "/help/" + page
		if anchor != "" {
			url += "#" + anchor
		}
		return fmt.Sprintf("[%s](%s)", text, url)
	})

	// Rewrite standard markdown links [Text](Target)
	md = mdLinkRegex.ReplaceAllStringFunc(md, func(match string) string {
		submatches := mdLinkRegex.FindStringSubmatch(match)
		if len(submatches) < 3 {
			return match
		}
		text := submatches[1]
		target := strings.TrimSpace(submatches[2])

		// Leave external, absolute, mailto, anchor-only, or static links untouched
		if strings.HasPrefix(target, "http://") ||
			strings.HasPrefix(target, "https://") ||
			strings.HasPrefix(target, "mailto:") ||
			strings.HasPrefix(target, "#") ||
			strings.HasPrefix(target, "/") {
			return match
		}

		// Relative wiki links (e.g., "Settings#oidc-enabled", "Root-Certificate")
		cleanTarget := strings.TrimPrefix(target, "./")
		parts := strings.SplitN(cleanTarget, "#", 2)
		pagePart := strings.TrimSuffix(parts[0], ".md")
		anchorPart := ""
		if len(parts) == 2 {
			anchorPart = "#" + parts[1]
		}

		return fmt.Sprintf("[%s](/help/%s%s)", text, pagePart, anchorPart)
	})

	return md
}

// renderWikiContent converts Markdown to HTML with goldmark and processes wiki links.
func renderWikiContent(rawContent string) (template.HTML, error) {
	processed := rewriteWikiLinks(rawContent)

	var buf bytes.Buffer
	if err := wikiGoldmark.Convert([]byte(processed), &buf); err != nil {
		return "", err
	}

	return template.HTML(buf.String()), nil
}

// showHelpPage renders the integrated help viewer.
func showHelpPage(c *gin.Context) {
	requestedPage := c.Param("page")
	if requestedPage == "" {
		requestedPage = "Home"
	}

	slug := sanitizeWikiSlug(requestedPage)
	wikiDir := getWikiDir()

	filePath, actualSlug, found := findWikiFile(wikiDir, slug)
	if !found {
		// If specific page not found, redirect to /help/Home or 404
		if slug != "Home" {
			c.Redirect(http.StatusSeeOther, "/help/Home")
			return
		}
		c.String(http.StatusNotFound, "Help documentation directory or Home.md not found")
		return
	}

	rawContent, err := os.ReadFile(filePath)
	if err != nil {
		log.Printf("Error reading wiki file %s: %v", filePath, err)
		c.String(http.StatusInternalServerError, "Failed to read documentation page")
		return
	}

	renderedHTML, err := renderWikiContent(string(rawContent))
	if err != nil {
		log.Printf("Error rendering markdown for %s: %v", filePath, err)
		c.String(http.StatusInternalServerError, "Failed to render documentation page")
		return
	}

	pages, err := getWikiPages(wikiDir, actualSlug)
	if err != nil {
		log.Printf("Error loading wiki pages: %v", err)
	}

	pageTitle := extractTitleFromMarkdown(filePath, actualSlug)

	// Check authentication state for navbar and session timer display
	isLoggedIn := false
	if store != nil {
		if session, err := store.Get(c.Request, "session"); err == nil {
			if auth, ok := session.Values["authenticated"].(bool); ok && auth {
				isLoggedIn = true
			}
		}
	}

	c.HTML(http.StatusOK, "help.html", gin.H{
		"pageTitle":   pageTitle,
		"activeSlug":  actualSlug,
		"content":     renderedHTML,
		"pages":       pages,
		"isLoggedIn":  isLoggedIn,
		"csrfToken":   getCSRFToken(c.Request),
	})
}
