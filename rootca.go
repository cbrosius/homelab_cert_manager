package main

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"net/http"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"software.sslmate.com/src/go-pkcs12"
)

func createRootCertificate(c *gin.Context) {
	commonName := c.PostForm("common_name")
	organization := c.PostForm("organization")
	organizationalUnit := c.PostForm("organizational_unit")
	country := c.PostForm("country")
	state := c.PostForm("state")
	locality := c.PostForm("locality")
	email := c.PostForm("email")
	validityYearsStr := c.PostForm("validity_years")

	if commonName == "" || validityYearsStr == "" {
		c.String(http.StatusBadRequest, "Common Name and Validity Period are mandatory fields.")
		return
	}

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

	rootCertTemplate := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			CommonName:         commonName,
			Organization:       []string{organization},
			OrganizationalUnit: []string{organizationalUnit},
			Country:            []string{country},
			Province:           []string{state},
			Locality:           []string{locality},
			ExtraNames: []pkix.AttributeTypeAndValue{
				{
					Type:  []int{1, 2, 840, 113549, 1, 9, 1},
					Value: email,
				},
			},
		},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().AddDate(validityYears, 0, 0),
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

	sanitizedCommonName := strings.ReplaceAll(commonName, " ", "_")
	rootCertFilename := "certs/" + sanitizedCommonName + ".pem"
	rootKeyFilename := "certs/" + sanitizedCommonName + ".key"
	rootPfxFilename := "certs/" + sanitizedCommonName + ".pfx"

	rootCertFile, err := os.Create(rootCertFilename)
	if err != nil {
		c.String(http.StatusInternalServerError, "Error creating root certificate file: %v", err)
		return
	}
	defer rootCertFile.Close()
	pem.Encode(rootCertFile, &pem.Block{Type: "CERTIFICATE", Bytes: rootCertBytes})

	rootKeyFile, err := os.Create(rootKeyFilename)
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

	rootPfxFile, err := os.Create(rootPfxFilename)
	if err != nil {
		c.String(http.StatusInternalServerError, "Error creating .pfx file: %v", err)
		return
	}
	defer rootPfxFile.Close()

	rootPfxFile.Write(rootPfxData)

	c.Redirect(http.StatusSeeOther, "/certificates")
}
