package main

import (
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"
)

// sanitizeFilename removes dangerous characters and path components from a filename
func sanitizeFilename(name string) string {
	// Remove path separators and parent directory references
	name = strings.ReplaceAll(name, "..", "")
	name = strings.ReplaceAll(name, "/", "_")
	name = strings.ReplaceAll(name, "\\", "_")

	// Remove any other dangerous characters
	// Allow: alphanumeric, spaces, dots, hyphens, underscores
	reg := regexp.MustCompile(`[^a-zA-Z0-9.\s\-_]`)
	name = reg.ReplaceAllString(name, "_")

	// Trim spaces and dots from ends
	name = strings.TrimSpace(name)
	name = strings.Trim(name, ".")

	return name
}

// getSafeCertPaths returns sanitized file paths for certificate files
func getSafeCertPaths(commonName string) (certPath, keyPath, pfxPath string, err error) {
	safeName := sanitizeFilename(commonName)

	if safeName == "" {
		return "", "", "", fmt.Errorf("invalid certificate name after sanitization")
	}

	certPath = filepath.Join("data", "certs", safeName+".pem")
	keyPath = filepath.Join("data", "certs", safeName+".key")
	pfxPath = filepath.Join("data", "certs", safeName+".pfx")

	return certPath, keyPath, pfxPath, nil
}

// createFileWithPermissions creates a file with specific permissions
func createFileWithPermissions(path string, perm os.FileMode) (*os.File, error) {
	return os.OpenFile(path, os.O_RDWR|os.O_CREATE|os.O_TRUNC, perm)
}
