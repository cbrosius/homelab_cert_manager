package main

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"log"
	"math/big"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/spf13/viper"
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

	if err := validateCommonName(commonName); err != nil {
		c.String(http.StatusBadRequest, err.Error())
		return
	}

	validityYears, err := validateValidityYears(validityYearsStr, 1, 100)
	if err != nil {
		c.String(http.StatusBadRequest, err.Error())
		return
	}

	if err := validateEmail(email); err != nil {
		c.String(http.StatusBadRequest, err.Error())
		return
	}

	if err := validateCountry(country); err != nil {
		c.String(http.StatusBadRequest, err.Error())
		return
	}

	privateKey, err := rsa.GenerateKey(rand.Reader, 4096)
	if err != nil {
		log.Printf("Error generating root private key: %v", err)
		c.String(http.StatusInternalServerError, "Error generating private key")
		return
	}

	serialNumber, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		log.Printf("Error generating root certificate serial number: %v", err)
		c.String(http.StatusInternalServerError, "Error generating serial number")
		return
	}

	rootCertTemplate := &x509.Certificate{
		SerialNumber: serialNumber,
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
		log.Printf("Error creating root certificate: %v", err)
		c.String(http.StatusInternalServerError, "Error creating root certificate")
		return
	}

	os.MkdirAll("data/root-cert", 0700)

	rootCertFilename := "data/root-cert/HomeLab_Root_CA.pem"
	rootKeyFilename := "data/root-cert/HomeLab_Root_CA.key"

	rootCertFile, err := createFileWithPermissions(rootCertFilename, 0644)
	if err != nil {
		log.Printf("Error creating root certificate file: %v", err)
		c.String(http.StatusInternalServerError, "Error creating root certificate file")
		return
	}
	defer rootCertFile.Close()
	pem.Encode(rootCertFile, &pem.Block{Type: "CERTIFICATE", Bytes: rootCertBytes})

	rootKeyFile, err := createFileWithPermissions(rootKeyFilename, 0600)
	if err != nil {
		log.Printf("Error creating root key file: %v", err)
		c.String(http.StatusInternalServerError, "Error creating root key file")
		return
	}
	defer rootKeyFile.Close()
	pem.Encode(rootKeyFile, &pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(privateKey)})

	// Save optional fields to settings.json
	viper.Set("general_cert_options.organization", strings.TrimSpace(organization))
	viper.Set("general_cert_options.organization_unit", strings.TrimSpace(organizationalUnit))
	viper.Set("general_cert_options.country", strings.TrimSpace(country))
	viper.Set("general_cert_options.state", strings.TrimSpace(state))
	viper.Set("general_cert_options.location", strings.TrimSpace(locality))
	viper.Set("general_cert_options.email", strings.TrimSpace(email))
	if err := viper.WriteConfig(); err != nil {
		log.Printf("Error saving settings after root certificate creation: %v", err)
		c.String(http.StatusInternalServerError, "Error saving settings")
		return
	}
	_ = os.Chmod("data/settings.json", 0600)

	c.Redirect(http.StatusSeeOther, "/certificates")
}

func deleteRootCertificate(c *gin.Context) {
	fileName := c.Param("filename")
	safeName := sanitizeFilename(strings.TrimSuffix(fileName, ".pem"))

	if safeName == "" {
		c.String(http.StatusBadRequest, "Invalid certificate name")
		return
	}

	filePathPem := filepath.Join("data", "root-cert", safeName+".pem")
	filePathKey := filepath.Join("data", "root-cert", safeName+".key")

	// Remove the .pem file
	if err := os.Remove(filePathPem); err != nil {
		log.Printf("Error deleting root certificate .pem file %s: %v", filePathPem, err)
		c.String(http.StatusInternalServerError, "Error deleting root certificate file")
		return
	}

	// Remove the .key file
	if err := os.Remove(filePathKey); err != nil && !os.IsNotExist(err) {
		log.Printf("Warning: Error deleting root certificate .key file %s: %v", filePathKey, err)
	}

	// Remove all files in the certs folder
	certFiles, err := os.ReadDir("./data/certs")
	if err != nil {
		log.Printf("Error reading certificates directory: %v", err)
		c.String(http.StatusInternalServerError, "Error reading certificates directory")
		return
	}

	for _, file := range certFiles {
		err = os.Remove("./data/certs/" + file.Name())
		if err != nil {
			log.Printf("Error deleting certificate file %s: %v", file.Name(), err)
			c.String(http.StatusInternalServerError, "Error deleting certificate file")
			return
		}
	}

	// Redirect to the index page to create a new root certificate
	c.Redirect(http.StatusSeeOther, "/")
}
