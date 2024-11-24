package main

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"log"
	"math/big"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"software.sslmate.com/src/go-pkcs12"
)

func listCertificates(c *gin.Context) {
	files, err := os.ReadDir("./data/certs")
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

func checkRootCertAndListCerts(c *gin.Context) {
	log.Println("checkRootCertAndListCerts called")

	var rootCert *x509.Certificate
	var rootCertFile string

	// Walk the root-cert directory and find the root certificate
	err := filepath.Walk("data/root-cert", func(path string, info os.FileInfo, err error) error {
		if err != nil {
			log.Printf("Error walking root-cert directory: %v", err)
			return err
		}
		if !info.IsDir() && filepath.Ext(info.Name()) == ".pem" {
			log.Printf("Found root certificate file: %s", path)
			rootCertBytes, err := os.ReadFile(path)
			if err != nil {
				log.Printf("Error reading root certificate file: %v", err)
				return err
			}
			block, _ := pem.Decode(rootCertBytes)
			if block == nil {
				log.Printf("Failed to parse root certificate PEM")
				return fmt.Errorf("failed to parse root certificate PEM")
			}
			rootCert, err = x509.ParseCertificate(block.Bytes)
			if err != nil {
				log.Printf("Error parsing root certificate: %v", err)
				return err
			}
			rootCertFile = strings.TrimSuffix(info.Name(), ".pem")
			log.Printf("Successfully parsed root certificate: %s", rootCert.Subject.CommonName)
			return filepath.SkipDir
		}
		return nil
	})

	if err != nil {
		c.String(http.StatusInternalServerError, "Error checking root-cert directory: %v", err)
		return
	}

	if rootCert == nil {
		c.Redirect(http.StatusSeeOther, "/")
		return
	}

	files, err := os.ReadDir("./data/certs")
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

	var rootCertDetails map[string]interface{}
	if rootCert != nil {
		rootCertDetails = map[string]interface{}{
			"CommonName": rootCert.Subject.CommonName,
			"Issuer":     rootCert.Issuer,
			"Subject":    rootCert.Subject,
			"NotBefore":  rootCert.NotBefore,
			"NotAfter":   rootCert.NotAfter,
			"Filename":   rootCertFile,
		}
		log.Printf("Root certificate details: %+v", rootCertDetails)
	} else {
		log.Printf("No root certificate found.")
	}

	c.HTML(http.StatusOK, "cert_list.html", gin.H{
		"rootCertificate": rootCertDetails,
		"certificates":    certs,
	})
}

func findRootCertAndKey() (*x509.Certificate, *rsa.PrivateKey, error) {
	var rootCert *x509.Certificate
	var rootKey *rsa.PrivateKey

	err := filepath.Walk("data/root-cert", func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		if !info.IsDir() {
			rootCertBytes, err := os.ReadFile(path)
			if err != nil {
				return err
			}
			block, _ := pem.Decode(rootCertBytes)
			if block == nil {
				return fmt.Errorf("failed to parse PEM block")
			}
			if strings.Contains(block.Type, "CERTIFICATE") {
				cert, err := x509.ParseCertificate(block.Bytes)
				if err != nil {
					return fmt.Errorf("failed to parse root certificate: %v", err)
				}
				rootCert = cert
			} else if strings.Contains(block.Type, "PRIVATE KEY") {
				key, err := x509.ParsePKCS1PrivateKey(block.Bytes)
				if err != nil {
					return fmt.Errorf("failed to parse root key: %v", err)
				}
				rootKey = key
			}
		}
		return nil
	})

	if err != nil {
		return nil, nil, err
	}
	if rootCert == nil || rootKey == nil {
		return nil, nil, fmt.Errorf("root certificate or key not found")
	}

	return rootCert, rootKey, nil
}

func createCertificate(c *gin.Context) {
	commonName := c.PostForm("common_name")
	dnsNames := c.PostFormArray("dns_names[]")
	ipAddresses := c.PostFormArray("ip_addresses[]")
	validityYearsStr := c.PostForm("validity_years")

	validityYears, err := strconv.Atoi(validityYearsStr)
	if err != nil {
		c.String(http.StatusBadRequest, "Invalid validity period: %v", err)
		return
	}

	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		c.String(http.StatusInternalServerError, "Error generating private key: %v", err)
		return
	}

	// Generate a random serial number
	serialNumber, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		c.String(http.StatusInternalServerError, "Error generating serial number: %v", err)
		return
	}

	certTemplate := &x509.Certificate{
		SerialNumber: serialNumber,
		Subject: pkix.Name{
			CommonName: commonName,
		},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().AddDate(validityYears, 0, 0),
		KeyUsage:              x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
	}

	certTemplate.DNSNames = append(certTemplate.DNSNames, dnsNames...)

	for _, ip := range ipAddresses {
		parsedIP := net.ParseIP(ip)
		if parsedIP != nil {
			certTemplate.IPAddresses = append(certTemplate.IPAddresses, parsedIP)
		}
	}

	// Find root certificate and key
	rootCert, rootKey, err := findRootCertAndKey()
	if err != nil {
		c.String(http.StatusInternalServerError, "Error finding root certificate or key: %v", err)
		return
	}

	certBytes, err := x509.CreateCertificate(rand.Reader, certTemplate, rootCert, &privateKey.PublicKey, rootKey)
	if err != nil {
		c.String(http.StatusInternalServerError, "Error creating certificate: %v", err)
		return
	}

	// Save the certificate in PEM format
	certFile, err := os.Create("data/certs/" + commonName + ".pem")
	if err != nil {
		c.String(http.StatusInternalServerError, "Error creating certificate file: %v", err)
		return
	}
	defer certFile.Close()
	pem.Encode(certFile, &pem.Block{Type: "CERTIFICATE", Bytes: certBytes})

	// Save the private key in PEM format
	keyFile, err := os.Create("data/certs/" + commonName + ".key")
	if err != nil {
		c.String(http.StatusInternalServerError, "Error creating key file: %v", err)
		return
	}
	defer keyFile.Close()
	pem.Encode(keyFile, &pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(privateKey)})

	// Create a .pfx file using Modern.Encode
	privateKeyAsCrypto := crypto.PrivateKey(privateKey) // Convert to the appropriate interface
	cert, err := x509.ParseCertificate(certBytes)       // Parse the raw certificate bytes
	if err != nil {
		c.String(http.StatusInternalServerError, "Error parsing certificate: %v", err)
		return
	}

	pfxData, err := pkcs12.Modern.Encode(privateKeyAsCrypto, cert, []*x509.Certificate{rootCert}, "")
	if err != nil {
		c.String(http.StatusInternalServerError, "Error creating .pfx file: %v", err)
		return
	}

	pfxFile, err := os.Create("data/certs/" + commonName + ".pfx")
	if err != nil {
		c.String(http.StatusInternalServerError, "Error creating .pfx file: %v", err)
		return
	}
	defer pfxFile.Close()
	_, err = pfxFile.Write(pfxData)
	if err != nil {
		c.String(http.StatusInternalServerError, "Error writing .pfx file: %v", err)
		return
	}

	c.Redirect(http.StatusSeeOther, "/certificates")
}

func downloadCertificate(c *gin.Context) {
	fileName := c.Param("filename")
	filePath := "./data/certs/" + fileName

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
	baseName := strings.TrimSuffix(fileName, filepath.Ext(fileName))
	certFilePath := "./data/certs/" + fileName
	keyFilePath := "./data/certs/" + baseName + ".key"
	pfxFilePath := "./data/certs/" + baseName + ".pfx"

	// Delete the certificate file
	err := os.Remove(certFilePath)
	if err != nil {
		c.String(http.StatusInternalServerError, "Error deleting certificate: %v", err)
		return
	}

	// Delete the key file
	err = os.Remove(keyFilePath)
	if err != nil {
		log.Printf("Warning: Error deleting key file: %v", err)
		// Don't return here, continue with deleting other files
	}

	// Delete the pfx file
	err = os.Remove(pfxFilePath)
	if err != nil {
		log.Printf("Warning: Error deleting pfx file: %v", err)
		// Don't return here, continue with deleting other files
	}

	// Redirect to the certificates list page after deletion
	c.Redirect(http.StatusSeeOther, "/certificates")
}

func viewCertificate(c *gin.Context) {
	fileName := c.Param("filename")
	filePath := "./data/certs/" + fileName

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
		// "encoded": string(content),
		"decoded": decoded,
	})
}
