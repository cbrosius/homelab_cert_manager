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
	"github.com/spf13/viper"
	"software.sslmate.com/src/go-pkcs12"
)

func convertIPsToStrings(ips []net.IP) []string {
	var ipStrings []string
	for _, ip := range ips {
		ipStrings = append(ipStrings, ip.String())
	}
	return ipStrings
}

func checkRootCertAndListCerts(c *gin.Context) {
	log.Println("checkRootCertAndListCerts called")

	// Get root certificate info
	rootCert, err := readCertificate("data/root-cert/HomeLab_Root_CA.pem")
	var rootCertInfo *x509.Certificate
	if err == nil {
		rootCertInfo = rootCert
	}

	// Check for self-signed certificate
	selfSignedExists := false
	if _, err := os.Stat("data/certmanager-cert/selfsigned.pem"); err == nil {
		selfSignedExists = true
	}

	// Check for homelab certificate
	homelabCertExists := false
	homelabCert, err := readCertificate("data/certmanager-cert/homelab_certificate_manager.pem")
	var homelabCertInfo *x509.Certificate
	if err == nil {
		homelabCertInfo = homelabCert
		homelabCertExists = true
	}

	files, err := os.ReadDir("./data/certs")
	if err != nil {
		c.String(http.StatusInternalServerError, "Unable to read certificates directory: %v", err)
		return
	}

	type CertInfo struct {
		Name       string
		CreatedAt  time.Time
		ValidUntil time.Time
		SANs       []string
	}

	certs := []CertInfo{}
	for _, file := range files {
		if file.Type().IsRegular() && strings.HasSuffix(file.Name(), ".pem") {
			name := strings.TrimSuffix(file.Name(), ".pem")
			cert, err := readCertificate(filepath.Join("./data/certs", file.Name()))
			if err != nil {
				log.Printf("Error reading certificate %s: %v", file.Name(), err)
				continue
			}
			certInfo := CertInfo{
				Name:       name,
				CreatedAt:  cert.NotBefore,
				ValidUntil: cert.NotAfter,
				SANs:       append(cert.DNSNames, convertIPsToStrings(cert.IPAddresses)...),
			}
			certs = append(certs, certInfo)
		}
	}

	var rootCertDetails map[string]interface{}
	if rootCert != nil {
		rootCertFile := "HomeLab_Root_CA.pem"
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

	isDefaultPassword := viper.GetString("password") == hashPassword("admin")

	c.HTML(http.StatusOK, "cert_list.html", gin.H{
		"defaultPassword":    isDefaultPassword,
		"rootCertificate":    rootCertInfo,
		"homelabCertificate": homelabCertInfo,
		"certificates":       certs,
		"selfSignedExists":   selfSignedExists,
		"homelabCertExists":  homelabCertExists,
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
	log.Printf("createCertificate ...")
	var form struct {
		CommonName       string   `form:"common_name" binding:"required"`
		ValidityYears    string   `form:"validity_years" binding:"required"`
		Organization     string   `form:"organization"`
		OrganizationUnit string   `form:"organization_unit"`
		Country          string   `form:"country"`
		State            string   `form:"state"`
		Location         string   `form:"location"`
		Email            string   `form:"email"`
		DnsNames         []string `form:"dns"`
		IpAddresses      []string `form:"ip"`
		Overwrite        string   `form:"overwrite"`
	}

	if err := c.ShouldBind(&form); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	validityYears, err := strconv.Atoi(form.ValidityYears)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid validity period"})
		return
	}

	// Check if a certificate with the same common name already exists
	certFilePath := "data/certs/" + form.CommonName + ".pem"
	if _, err := os.Stat(certFilePath); err == nil {
		// Certificate already exists, prompt user for confirmation
		overwrite := c.PostForm("overwrite")
		if overwrite != "yes" {
			c.JSON(http.StatusOK, gin.H{"error": "A certificate with the same common name already exists. Do you want to overwrite it?"})
			return
		}
	}

	serialNumber, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Error generating serial number"})
		return
	}

	// Create new certificate template
	certTemplate := &x509.Certificate{
		SerialNumber: serialNumber,
		Subject: pkix.Name{
			CommonName:         form.CommonName,
			Organization:       []string{form.Organization},
			OrganizationalUnit: []string{form.OrganizationUnit},
			Country:            []string{form.Country},
			Province:           []string{form.State},
			Locality:           []string{form.Location},
			ExtraNames: []pkix.AttributeTypeAndValue{
				{
					Type:  []int{1, 2, 840, 113549, 1, 9, 1},
					Value: form.Email,
				},
			},
		},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().AddDate(validityYears, 0, 0),
		KeyUsage:              x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
	}

	// Generate private key and certificate
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Error generating private key"})
		return
	}

	for _, dns := range form.DnsNames {
		if dns != "" {
			certTemplate.DNSNames = append(certTemplate.DNSNames, dns)
		}
	}
	log.Printf("DNS-Names: %v", certTemplate.DNSNames)

	for _, ip := range form.IpAddresses {
		if parsedIP := net.ParseIP(ip); parsedIP != nil {
			certTemplate.IPAddresses = append(certTemplate.IPAddresses, parsedIP)
		}
	}
	log.Printf("IP Addresses: %v", certTemplate.IPAddresses)

	rootCert, rootKey, err := findRootCertAndKey()
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Error finding root certificate or key"})
		return
	}

	certBytes, err := x509.CreateCertificate(rand.Reader, certTemplate, rootCert, &privateKey.PublicKey, rootKey)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Error creating certificate"})
		return
	}

	certFile, err := os.Create(certFilePath)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Error creating certificate file"})
		return
	}
	defer certFile.Close()
	if err := pem.Encode(certFile, &pem.Block{Type: "CERTIFICATE", Bytes: certBytes}); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Error encoding certificate file"})
		return
	}

	keyFile, err := os.Create("data/certs/" + form.CommonName + ".key")
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Error creating key file"})
		return
	}
	defer keyFile.Close()
	if err := pem.Encode(keyFile, &pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(privateKey)}); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Error encoding key file"})
		return
	}

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

	pfxFile, err := os.Create("data/certs/" + form.CommonName + ".pfx")
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

	c.JSON(http.StatusOK, gin.H{"message": "Certificate created successfully", "redirect": "/certificates"})
}

func downloadCertificate(c *gin.Context) {
	certType := c.Param("certType")
	fileName := c.Param("filename")
	var filePath string

	switch certType {
	case "root-cert":
		filePath = filepath.Join("data", "root-cert", fileName)
	case "certs":
		filePath = filepath.Join("data", "certs", fileName)
	default:
		c.String(http.StatusBadRequest, "Invalid certificate type")
		return
	}

	if _, err := os.Stat(filePath); os.IsNotExist(err) {
		c.String(http.StatusNotFound, "File not found")
		return
	}

	c.Header("Content-Description", "File Transfer")
	c.Header("Content-Transfer-Encoding", "binary")
	c.Header("Content-Disposition", fmt.Sprintf("attachment; filename=%s", fileName))

	switch {
	case strings.HasSuffix(fileName, ".pem"):
		c.Header("Content-Type", "application/x-pem-file")
	case strings.HasSuffix(fileName, ".key"):
		c.Header("Content-Type", "application/x-pem-file")
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
	var filePath string

	// Clean the filename to prevent path traversal
	cleanFileName := filepath.Base(fileName)

	// Special case for homelab certificate manager certificate
	if cleanFileName == "homelab_certificate_manager.pem" {
		filePath = filepath.Join("data", "certmanager-cert", cleanFileName)
	} else {
		filePath = filepath.Join("data", "certs", cleanFileName)
	}

	// Check if the file exists
	if _, err := os.Stat(filePath); os.IsNotExist(err) {
		c.String(http.StatusNotFound, "File not found")
		return
	}

	// Read and decode the certificate
	cert, err := readCertificate(filePath)
	if err != nil {
		c.String(http.StatusInternalServerError, err.Error())
		return
	}

	// Create a decoded view of the certificate
	decoded := fmt.Sprintf(
		"Issuer: %s\nSubject: %s\nValidity:\n  Not Before: %s\n  Not After : %s\n",
		cert.Issuer, cert.Subject, cert.NotBefore, cert.NotAfter,
	)

	// Check for SubjectAlternativeName and IP Addresses
	if len(cert.DNSNames) > 0 || len(cert.IPAddresses) > 0 {
		decoded += "Subject Alternative Names:\n"
		for _, dns := range cert.DNSNames {
			decoded += fmt.Sprintf("  DNS: %s\n", dns)
		}
		for _, ip := range cert.IPAddresses {
			decoded += fmt.Sprintf("  IP: %s\n", ip.String())
		}
	}

	// Return the file content and decoded view as JSON
	c.JSON(http.StatusOK, gin.H{
		"decoded": decoded,
	})
}

func readCertificate(filePath string) (*x509.Certificate, error) {
	content, err := os.ReadFile(filePath)
	if err != nil {
		return nil, fmt.Errorf("error reading certificate: %v", err)
	}

	block, _ := pem.Decode(content)
	if block == nil {
		return nil, fmt.Errorf("failed to parse certificate PEM")
	}

	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("failed to parse certificate: %v", err)
	}

	return cert, nil
}

func recreateHomelabCertificate(c *gin.Context) {
	// First check if root certificate exists
	rootCert, rootKey, err := loadRootCertAndKey()
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Root certificate not found"})
		return
	}

	// Generate new key pair
	certKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to generate private key"})
		return
	}

	// Create certificate template
	serialNumber, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to generate serial number"})
		return
	}
	template := x509.Certificate{
		SerialNumber: serialNumber,
		Subject: pkix.Name{
			CommonName: "HomeLab Certificate Manager",
		},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().AddDate(10, 0, 0),
		KeyUsage:              x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
	}

	// Load DNS names and IP addresses from settings
	settingsDnsNames := viper.GetStringSlice("certificate_manager_certificate.dns_names")
	log.Printf("Loaded DNS Names: %v", settingsDnsNames)
	// Append DNS names from settings
	for _, dns := range settingsDnsNames {
		if dns != "" {
			template.DNSNames = append(template.DNSNames, dns)
		}
	}

	// Append IP addresses from settings
	settingsIpAddresses := viper.GetStringSlice("certificate_manager_certificate.ip_addresses")
	log.Printf("Loaded IP Addresses: %v", settingsIpAddresses)
	for _, ip := range settingsIpAddresses {
		if parsedIP := net.ParseIP(ip); parsedIP != nil {
			template.IPAddresses = append(template.IPAddresses, parsedIP)
		} else {
			log.Printf("Invalid IP address: %s", ip)
		}
	}

	// Load organization details from settings
	template.Subject.Organization = []string{viper.GetString("general_cert_options.organization")}
	template.Subject.OrganizationalUnit = []string{viper.GetString("general_cert_options.organization_unit")}
	template.Subject.Country = []string{viper.GetString("general_cert_options.country")}
	template.Subject.Province = []string{viper.GetString("general_cert_options.state")}
	template.Subject.Locality = []string{viper.GetString("general_cert_options.location")}

	// Create certificate signed by root CA
	certBytes, err := x509.CreateCertificate(rand.Reader, &template, rootCert, &certKey.PublicKey, rootKey)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to create certificate"})
		return
	}

	// Save new private key
	keyFile, err := os.Create("data/certmanager-cert/homelab_certificate_manager.key")
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to save private key"})
		return
	}
	defer keyFile.Close()
	pem.Encode(keyFile, &pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(certKey)})

	// Save new certificate
	certFile, err := os.Create("data/certmanager-cert/homelab_certificate_manager.pem")
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to save certificate"})
		return
	}
	defer certFile.Close()
	pem.Encode(certFile, &pem.Block{Type: "CERTIFICATE", Bytes: certBytes})

	c.JSON(http.StatusOK, gin.H{"message": "Certificate recreated successfully"})
}
