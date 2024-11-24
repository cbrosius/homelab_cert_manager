package main

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"math/big"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"software.sslmate.com/src/go-pkcs12"
)

func listCertificates(c *gin.Context) {
	files, err := os.ReadDir("./certs")
	if err != nil {
		c.String(http.StatusInternalServerError, "Unable to read certificates directory: %v", err)
		return
	}

	certs := []string{}
	for _, file := range files {
		if file.Type().IsRegular() && strings.HasSuffix(file.Name(), ".pem") {
			name := strings.TrimSuffix(file.Name(), ".pem")
			certs = append(certs, name)
		}
	}

	c.HTML(http.StatusOK, "cert_list.html", gin.H{
		"certificates": certs,
	})
}

func createCertificate(c *gin.Context) {
	commonName := c.PostForm("common_name")

	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		c.String(http.StatusInternalServerError, "Error generating private key: %v", err)
		return
	}

	certTemplate := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			CommonName: commonName,
		},
		NotBefore: time.Now(),
		NotAfter:  time.Now().AddDate(1, 0, 0),
		KeyUsage:  x509.KeyUsageDigitalSignature,
	}

	rootCertPEM, err := os.ReadFile("certs/rootCA.pem")
	if err != nil {
		c.String(http.StatusInternalServerError, "Error reading root certificate: %v", err)
		return
	}
	rootCertBlock, _ := pem.Decode(rootCertPEM)
	rootCert, err := x509.ParseCertificate(rootCertBlock.Bytes)
	if err != nil {
		c.String(http.StatusInternalServerError, "Error parsing root certificate: %v", err)
		return
	}

	rootKeyPEM, err := os.ReadFile("certs/rootCA.key")
	if err != nil {
		c.String(http.StatusInternalServerError, "Error reading root private key: %v", err)
		return
	}
	rootKeyBlock, _ := pem.Decode(rootKeyPEM)
	rootKey, err := x509.ParsePKCS1PrivateKey(rootKeyBlock.Bytes)
	if err != nil {
		c.String(http.StatusInternalServerError, "Error parsing root private key: %v", err)
		return
	}

	certBytes, err := x509.CreateCertificate(rand.Reader, certTemplate, rootCert, &privateKey.PublicKey, rootKey)
	if err != nil {
		c.String(http.StatusInternalServerError, "Error creating certificate: %v", err)
		return
	}

	certFile, err := os.Create(fmt.Sprintf("certs/%s.pem", commonName))
	if err != nil {
		c.String(http.StatusInternalServerError, "Error creating certificate file: %v", err)
		return
	}
	defer certFile.Close()
	pem.Encode(certFile, &pem.Block{Type: "CERTIFICATE", Bytes: certBytes})

	keyFile, err := os.Create(fmt.Sprintf("certs/%s.key", commonName))
	if err != nil {
		c.String(http.StatusInternalServerError, "Error creating key file: %v", err)
		return
	}
	defer keyFile.Close()
	pem.Encode(keyFile, &pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(privateKey)})

	// Generate .pfx file
	pfxData, err := pkcs12.Encode(rand.Reader, privateKey, &x509.Certificate{
		Raw: certBytes,
	}, []*x509.Certificate{rootCert}, "")
	if err != nil {
		c.String(http.StatusInternalServerError, "Error creating .pfx file: %v", err)
		return
	}

	pfxFile, err := os.Create(fmt.Sprintf("certs/%s.pfx", commonName))
	if err != nil {
		c.String(http.StatusInternalServerError, "Error creating .pfx file: %v", err)
		return
	}
	defer pfxFile.Close()
	pfxFile.Write(pfxData)

	// Redirect to the certificates list page after creation
	c.Redirect(http.StatusSeeOther, "/certificates")
}

func downloadCertificate(c *gin.Context) {
	fileName := c.Param("filename")
	filePath := "./certs/" + fileName

	c.Header("Content-Description", "File Transfer")
	c.Header("Content-Transfer-Encoding", "binary")
	c.Header("Content-Disposition", fmt.Sprintf("attachment; filename=%s", fileName))
	switch {
	case strings.HasSuffix(fileName, ".pem"):
		c.Header("Content-Type", "application/x-pem-file")
	case strings.HasSuffix(fileName, ".key"):
		c.Header("Content-Type", "application/x-iwork-keynote-sffkey")
	case strings.HasSuffix(fileName, ".pfx"):
		c.Header("Content-Type", "application/x-pkcs12")
	default:
		c.Header("Content-Type", "application/octet-stream")
	}
	c.File(filePath)
}

func deleteCertificate(c *gin.Context) {
	fileName := c.Param("filename")
	filePath := "./certs/" + fileName

	err := os.Remove(filePath)
	if err != nil {
		c.String(http.StatusInternalServerError, "Error deleting certificate: %v", err)
		return
	}

	// Redirect to the certificates list page after deletion
	c.Redirect(http.StatusSeeOther, "/certificates")
}

func viewCertificate(c *gin.Context) {
	fileName := c.Param("filename")
	filePath := "./certs/" + fileName

	// Check if the file exists
	if _, err := os.Stat(filePath); os.IsNotExist(err) {
		c.String(http.StatusNotFound, "File not found")
		return
	}

	// Read the file content
	content, err := os.ReadFile(filePath)
	if err != nil {
		c.String(http.StatusInternalServerError, "Error reading certificate: %v", err)
		return
	}

	// Decode the certificate
	block, _ := pem.Decode(content)
	if block == nil {
		c.String(http.StatusInternalServerError, "Failed to parse certificate PEM")
		return
	}

	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		c.String(http.StatusInternalServerError, "Failed to parse certificate: %v", err)
		return
	}

	// Create a decoded view of the certificate
	decoded := fmt.Sprintf("Issuer: %s\nSubject: %s\nValidity:\n  Not Before: %s\n  Not After : %s\n", cert.Issuer, cert.Subject, cert.NotBefore, cert.NotAfter)

	// Return the file content and decoded view as JSON
	c.JSON(http.StatusOK, gin.H{
		"encoded": string(content),
		"decoded": decoded,
	})
}

func createRootCertificate(c *gin.Context) {
	organization := c.PostForm("organization")

	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		c.String(http.StatusInternalServerError, "Error generating private key: %v", err)
		return
	}

	rootCertTemplate := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			Organization: []string{organization},
		},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().AddDate(10, 0, 0),
		IsCA:                  true,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
	}

	rootCertBytes, err := x509.CreateCertificate(rand.Reader, rootCertTemplate, rootCertTemplate, &privateKey.PublicKey, privateKey)
	if err != nil {
		c.String(http.StatusInternalServerError, "Error creating root certificate: %v", err)
		return
	}

	os.MkdirAll("certs", os.ModePerm)

	rootCertFile, err := os.Create("certs/rootCA.pem")
	if err != nil {
		c.String(http.StatusInternalServerError, "Error creating root certificate file: %v", err)
		return
	}
	defer rootCertFile.Close()
	pem.Encode(rootCertFile, &pem.Block{Type: "CERTIFICATE", Bytes: rootCertBytes})

	rootKeyFile, err := os.Create("certs/rootCA.key")
	if err != nil {
		c.String(http.StatusInternalServerError, "Error creating root key file: %v", err)
		return
	}
	defer rootKeyFile.Close()
	pem.Encode(rootKeyFile, &pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(privateKey)})

	// Generate .pfx file for root certificate
	rootCert, err := x509.ParseCertificate(rootCertBytes)
	if err != nil {
		c.String(http.StatusInternalServerError, "Error parsing root certificate: %v", err)
		return
	}

	rootPfxData, err := pkcs12.Encode(rand.Reader, privateKey, rootCert, nil, "")
	if err != nil {
		c.String(http.StatusInternalServerError, "Error creating .pfx file: %v", err)
		return
	}

	rootPfxFile, err := os.Create("certs/rootCA.pfx")
	if err != nil {
		c.String(http.StatusInternalServerError, "Error creating .pfx file: %v", err)
		return
	}
	defer rootPfxFile.Close()

	rootPfxFile.Write(rootPfxData)

	c.Redirect(http.StatusSeeOther, "/")
}
