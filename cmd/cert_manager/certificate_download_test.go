package main

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gin-gonic/gin"
)

func TestDownloadRootCertKeyBlocked(t *testing.T) {
	gin.SetMode(gin.TestMode)
	r := gin.New()
	r.GET("/certificates/download/root-cert/:filename", func(c *gin.Context) {
		c.Params = append(c.Params, gin.Param{Key: "certType", Value: "root-cert"})
		downloadCertificate(c)
	})

	// Attempt to download the Root CA private key
	req, _ := http.NewRequest(http.MethodGet, "/certificates/download/root-cert/HomeLab_Root_CA.key", nil)
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	if w.Code != http.StatusForbidden {
		t.Fatalf("Expected 403 Forbidden when downloading Root CA key, got %d. Body: %s", w.Code, w.Body.String())
	}
}

func TestDownloadCertManagerCertKeyBlocked(t *testing.T) {
	gin.SetMode(gin.TestMode)
	r := gin.New()
	r.GET("/certificates/download/certmanager-cert/:filename", func(c *gin.Context) {
		c.Params = append(c.Params, gin.Param{Key: "certType", Value: "certmanager-cert"})
		downloadCertificate(c)
	})

	// Attempt to download the Certificate Manager private key
	req, _ := http.NewRequest(http.MethodGet, "/certificates/download/certmanager-cert/homelab_certificate_manager.key", nil)
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	if w.Code != http.StatusForbidden {
		t.Fatalf("Expected 403 Forbidden when downloading Certificate Manager key, got %d. Body: %s", w.Code, w.Body.String())
	}
}

func TestDownloadCertInvalidExtensionsBlocked(t *testing.T) {
	gin.SetMode(gin.TestMode)
	r := gin.New()
	r.GET("/certificates/download/:filename", func(c *gin.Context) {
		c.Params = append(c.Params, gin.Param{Key: "certType", Value: "certs"})
		downloadCertificate(c)
	})

	disallowedFiles := []string{
		"settings.json",
		"config.yaml",
		"malicious.exe",
		"script.sh",
		"file.txt",
	}

	for _, filename := range disallowedFiles {
		req, _ := http.NewRequest(http.MethodGet, "/certificates/download/"+filename, nil)
		w := httptest.NewRecorder()
		r.ServeHTTP(w, req)

		if w.Code != http.StatusBadRequest {
			t.Errorf("Expected 400 Bad Request for disallowed file %q, got %d", filename, w.Code)
		}
	}
}

func TestDownloadCertPathTraversalBlocked(t *testing.T) {
	gin.SetMode(gin.TestMode)
	r := gin.New()
	r.GET("/certificates/download/:filename", func(c *gin.Context) {
		c.Params = append(c.Params, gin.Param{Key: "certType", Value: "certs"})
		downloadCertificate(c)
	})

	traversalFilenames := []string{
		"..%2f..%2fsettings.json",
		"....//data/certs/cert.pem",
	}

	for _, filename := range traversalFilenames {
		req, _ := http.NewRequest(http.MethodGet, "/certificates/download/"+filename, nil)
		w := httptest.NewRecorder()
		r.ServeHTTP(w, req)

		if w.Code != http.StatusBadRequest && w.Code != http.StatusNotFound {
			t.Errorf("Expected traversal %q to be blocked with 400 or 404, got %d", filename, w.Code)
		}
	}
}

func TestViewCertificateValidation(t *testing.T) {
	gin.SetMode(gin.TestMode)
	r := gin.New()
	r.GET("/certificates/view/:filename", viewCertificate)

	invalidFiles := []string{
		"service.key",
		"settings.json",
		"test.exe",
	}

	for _, filename := range invalidFiles {
		req, _ := http.NewRequest(http.MethodGet, "/certificates/view/"+filename, nil)
		w := httptest.NewRecorder()
		r.ServeHTTP(w, req)

		if w.Code != http.StatusBadRequest {
			t.Errorf("Expected 400 Bad Request for invalid view file %q, got %d", filename, w.Code)
		}
	}
}

func TestIsValidFileName(t *testing.T) {
	valid := []string{
		"mycert.pem",
		"HomeLab_Root_CA.pem",
		"server.crt",
	}
	for _, f := range valid {
		if !isValidFileName(f) {
			t.Errorf("Expected isValidFileName(%q) to be true", f)
		}
	}

	invalid := []string{
		"",
		"mycert.key",
		"mycert.pfx",
		"../mycert.pem",
		"subdir/mycert.pem",
		`subdir\mycert.pem`,
		"mycert.json",
	}
	for _, f := range invalid {
		if isValidFileName(f) {
			t.Errorf("Expected isValidFileName(%q) to be false", f)
		}
	}
}
