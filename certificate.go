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
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/spf13/viper"
	"software.sslmate.com/src/go-pkcs12"
)

// mimeTypes maps file extensions to their corresponding MIME types.
// Extensions include the leading dot and should be lowercase.
var mimeTypes = map[string]string{
	".pem": "application/x-pem-file",
	".key": "application/x-pem-file",
	".pfx": "application/x-pkcs12",
	".p12": "application/x-pkcs12",
	".crt": "application/x-x509-ca-cert",
	".cer": "application/x-x509-ca-cert",
	".der": "application/x-x509-ca-cert",
}

// getContentType returns the MIME type for a given filename.
// Returns "application/octet-stream" as the default for unknown extensions.
// The lookup is case-insensitive.
func getContentType(fileName string) string {
	ext := strings.ToLower(filepath.Ext(fileName))
	if contentType, ok := mimeTypes[ext]; ok {
		return contentType
	}
	return "application/octet-stream"
}

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
		log.Printf("Unable to read certificates directory: %v", err)
		c.String(http.StatusInternalServerError, "Unable to read certificates directory")
		return
	}

	type CertInfo struct {
		Name          string
		CreatedAt     time.Time
		ValidUntil    time.Time
		SANs          []string
		HasPrivateKey bool
		Ext           string
	}

	certs := []CertInfo{}
	seen := make(map[string]bool)
	for _, file := range files {
		if !file.Type().IsRegular() {
			continue
		}
		var name string
		var ext string
		if strings.HasSuffix(file.Name(), ".pem") {
			name = strings.TrimSuffix(file.Name(), ".pem")
			ext = "pem"
		} else if strings.HasSuffix(file.Name(), ".crt") {
			name = strings.TrimSuffix(file.Name(), ".crt")
			ext = "crt"
		} else {
			continue
		}

		if seen[name] {
			continue
		}
		seen[name] = true

		cert, err := readCertificate(filepath.Join("./data/certs", file.Name()))
		if err != nil {
			log.Printf("Error reading certificate %s: %v", file.Name(), err)
			continue
		}

		hasKey := false
		if _, err := os.Stat(filepath.Join("./data/certs", name+".key")); err == nil {
			hasKey = true
		}

		certInfo := CertInfo{
			Name:          name,
			CreatedAt:     cert.NotBefore,
			ValidUntil:    cert.NotAfter,
			SANs:          append(cert.DNSNames, convertIPsToStrings(cert.IPAddresses)...),
			HasPrivateKey: hasKey,
			Ext:           ext,
		}
		certs = append(certs, certInfo)
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

	isDefaultPassword := checkPasswordHash("admin", viper.GetString("password"))

	defaultValidityDays := 365
	if period := viper.GetInt("general_cert_options.validity_period"); period > 0 {
		defaultValidityDays = period * 365
	}

	c.HTML(http.StatusOK, "cert_list.html", gin.H{
		"defaultPassword":     isDefaultPassword,
		"rootCertificate":     rootCertInfo,
		"homelabCertificate":  homelabCertInfo,
		"certificates":        certs,
		"selfSignedExists":    selfSignedExists,
		"homelabCertExists":   homelabCertExists,
		"defaultValidityDays": defaultValidityDays,
		"csrfToken":           getCSRFToken(c.Request),
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
	debugLog("createCertificate called")
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

	// Ensure Root CA exists before attempting certificate creation
	rootCert, rootKey, err := findRootCertAndKey()
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "No Root CA certificate found. Please create a Root CA before issuing certificates."})
		return
	}

	form.CommonName = strings.TrimSpace(form.CommonName)
	if err := validateCommonName(form.CommonName); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	validityYears, err := validateValidityYears(form.ValidityYears, 1, 100)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	if err := validateEmail(form.Email); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	if err := validateCountry(form.Country); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	// Validate and collect DNS names
	var validDNSNames []string
	for _, dns := range form.DnsNames {
		dns = strings.TrimSpace(dns)
		if dns == "" {
			continue
		}
		if err := validateDNSName(dns); err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
			return
		}
		validDNSNames = append(validDNSNames, dns)
	}

	// Validate and collect IP addresses
	var validIPAddresses []net.IP
	for _, ipStr := range form.IpAddresses {
		ipStr = strings.TrimSpace(ipStr)
		if ipStr == "" {
			continue
		}
		parsedIP, err := validateIPAddress(ipStr)
		if err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
			return
		}
		if parsedIP != nil {
			validIPAddresses = append(validIPAddresses, parsedIP)
		}
	}

	// Use sanitized paths to prevent path traversal attacks
	certFilePath, keyFilePath, pfxFilePath, err := getSafeCertPaths(form.CommonName)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid certificate name"})
		return
	}

	// Check if a certificate with the same common name already exists
	if _, err := os.Stat(certFilePath); err == nil {
		// Certificate already exists, prompt user for confirmation
		overwrite := c.PostForm("overwrite")
		if overwrite != "yes" {
			c.JSON(http.StatusOK, gin.H{
				"error":             "A certificate with the same common name already exists. Do you want to overwrite it?",
				"needsConfirmation": true,
			})
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
		DNSNames:              validDNSNames,
		IPAddresses:           validIPAddresses,
	}

	debugLog("DNS-Names: %v", certTemplate.DNSNames)
	debugLog("IP Addresses: %v", certTemplate.IPAddresses)

	// Generate private key and certificate
	privateKey, err := rsa.GenerateKey(rand.Reader, 4096)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Error generating private key"})
		return
	}

	certBytes, err := x509.CreateCertificate(rand.Reader, certTemplate, rootCert, &privateKey.PublicKey, rootKey)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Error creating certificate"})
		return
	}

	certFile, err := createFileWithPermissions(certFilePath, 0644)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Error creating certificate file"})
		return
	}
	defer certFile.Close()
	if err := pem.Encode(certFile, &pem.Block{Type: "CERTIFICATE", Bytes: certBytes}); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Error encoding certificate file"})
		return
	}

	keyFile, err := createFileWithPermissions(keyFilePath, 0600)
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
		log.Printf("Error parsing certificate: %v", err)
		c.String(http.StatusInternalServerError, "Error parsing certificate")
		return
	}

	pfxData, err := pkcs12.Modern.Encode(privateKeyAsCrypto, cert, []*x509.Certificate{rootCert}, "")
	if err != nil {
		log.Printf("Error creating .pfx file: %v", err)
		c.String(http.StatusInternalServerError, "Error creating .pfx file")
		return
	}

	pfxFile, err := createFileWithPermissions(pfxFilePath, 0600)
	if err != nil {
		log.Printf("Error creating .pfx file: %v", err)
		c.String(http.StatusInternalServerError, "Error creating .pfx file")
		return
	}
	defer pfxFile.Close()
	_, err = pfxFile.Write(pfxData)
	if err != nil {
		log.Printf("Error writing .pfx file: %v", err)
		c.String(http.StatusInternalServerError, "Error writing .pfx file")
		return
	}

	c.JSON(http.StatusOK, gin.H{"message": "Certificate created successfully", "redirect": "/certificates"})
}

func downloadCertificate(c *gin.Context) {
	certType := c.Param("certType")
	fileName := c.Param("filename")

	// Validate filename: must not be empty, must be a base filename without directory traversal
	if fileName == "" || filepath.Base(fileName) != fileName || strings.Contains(fileName, "..") || strings.ContainsAny(fileName, `/\`) {
		c.String(http.StatusBadRequest, "Invalid file name")
		return
	}

	ext := strings.ToLower(filepath.Ext(fileName))
	baseName := strings.TrimSuffix(fileName, filepath.Ext(fileName))
	safeBaseName := sanitizeFilename(baseName)
	if safeBaseName == "" || safeBaseName != baseName {
		c.String(http.StatusBadRequest, "Invalid file name")
		return
	}

	safeFileName := safeBaseName + ext
	var baseDir string

	switch certType {
	case "root-cert":
		// Security: Under NO circumstances allow downloading Root CA private keys (.key)
		if ext != ".pem" && ext != ".crt" {
			c.String(http.StatusForbidden, "Downloading this file type is forbidden for Root CA")
			return
		}
		baseDir = filepath.Join("data", "root-cert")

	case "certs":
		// Security: Only allow downloading authorized certificate and key formats
		allowedExts := map[string]bool{
			".pem": true,
			".crt": true,
			".key": true,
			".pfx": true,
			".p12": true,
		}
		if !allowedExts[ext] {
			c.String(http.StatusBadRequest, "Invalid certificate file extension")
			return
		}
		baseDir = filepath.Join("data", "certs")

	default:
		c.String(http.StatusBadRequest, "Invalid certificate type")
		return
	}

	filePath := filepath.Join(baseDir, safeFileName)

	// Additional path containment check
	cleanBaseDir := filepath.Clean(baseDir) + string(filepath.Separator)
	cleanFilePath := filepath.Clean(filePath)
	if !strings.HasPrefix(cleanFilePath, cleanBaseDir) {
		c.String(http.StatusBadRequest, "Invalid file path")
		return
	}

	if _, err := os.Stat(filePath); os.IsNotExist(err) {
		// Fallback check between .pem and .crt
		if ext == ".pem" {
			altPath := filepath.Join(baseDir, safeBaseName+".crt")
			if _, err := os.Stat(altPath); err == nil {
				filePath = altPath
				safeFileName = safeBaseName + ".crt"
			}
		} else if ext == ".crt" {
			altPath := filepath.Join(baseDir, safeBaseName+".pem")
			if _, err := os.Stat(altPath); err == nil {
				filePath = altPath
				safeFileName = safeBaseName + ".pem"
			}
		}
	}

	if _, err := os.Stat(filePath); os.IsNotExist(err) {
		c.String(http.StatusNotFound, "File not found")
		return
	}

	c.Header("Content-Description", "File Transfer")
	c.Header("Content-Transfer-Encoding", "binary")
	c.Header("Content-Disposition", fmt.Sprintf("attachment; filename=%s", safeFileName))

	c.Header("Content-Type", getContentType(safeFileName))
	c.Header("X-Content-Type-Options", "nosniff")

	c.File(filePath)
}

func deleteCertificate(c *gin.Context) {
	fileName := c.Param("filename")
	baseName := strings.TrimSuffix(fileName, filepath.Ext(fileName))
	safeBaseName := sanitizeFilename(baseName)

	if safeBaseName == "" {
		c.String(http.StatusBadRequest, "Invalid certificate name")
		return
	}

	certPemPath := filepath.Join("data", "certs", safeBaseName+".pem")
	certCrtPath := filepath.Join("data", "certs", safeBaseName+".crt")
	keyFilePath := filepath.Join("data", "certs", safeBaseName+".key")
	pfxFilePath := filepath.Join("data", "certs", safeBaseName+".pfx")

	// Delete the certificate file (.pem or .crt)
	errPem := os.Remove(certPemPath)
	errCrt := os.Remove(certCrtPath)
	if errPem != nil && errCrt != nil && !os.IsNotExist(errPem) && !os.IsNotExist(errCrt) {
		log.Printf("Error deleting certificate %s: %v / %v", safeBaseName, errPem, errCrt)
		c.String(http.StatusInternalServerError, "Error deleting certificate")
		return
	}

	// Delete the key file (best effort, log but don't fail)
	if err := os.Remove(keyFilePath); err != nil && !os.IsNotExist(err) {
		log.Printf("Warning: Error deleting key file %s: %v", keyFilePath, err)
	}

	// Delete the pfx file (best effort, log but don't fail)
	if err := os.Remove(pfxFilePath); err != nil && !os.IsNotExist(err) {
		log.Printf("Warning: Error deleting pfx file %s: %v", pfxFilePath, err)
	}

	// Redirect to the certificates list page after deletion
	c.Redirect(http.StatusSeeOther, "/certificates")
}

func viewCertificate(c *gin.Context) {
	fileName := c.Param("filename")

	if !isValidFileName(fileName) {
		c.String(http.StatusBadRequest, "Invalid file name")
		return
	}

	ext := strings.ToLower(filepath.Ext(fileName))
	baseName := strings.TrimSuffix(fileName, filepath.Ext(fileName))
	safeBaseName := sanitizeFilename(baseName)
	if safeBaseName == "" || safeBaseName != baseName {
		c.String(http.StatusBadRequest, "Invalid file name")
		return
	}
	safeFileName := safeBaseName + ext

	var filePath string
	if safeFileName == "homelab_certificate_manager.pem" {
		filePath = filepath.Join("data", "certmanager-cert", safeFileName)
	} else {
		filePath = filepath.Join("data", "certs", safeFileName)
	}

	// Check if the file exists, with fallback between .pem and .crt
	if _, err := os.Stat(filePath); os.IsNotExist(err) {
		if ext == ".pem" {
			altPath := filepath.Join(filepath.Dir(filePath), safeBaseName+".crt")
			if _, err := os.Stat(altPath); err == nil {
				filePath = altPath
			}
		} else if ext == ".crt" {
			altPath := filepath.Join(filepath.Dir(filePath), safeBaseName+".pem")
			if _, err := os.Stat(altPath); err == nil {
				filePath = altPath
			}
		}
	}

	if _, err := os.Stat(filePath); os.IsNotExist(err) {
		c.String(http.StatusNotFound, "File not found")
		return
	}

	// Read and decode the certificate
	cert, err := readCertificate(filePath)
	if err != nil {
		log.Printf("Error reading certificate %s: %v", filePath, err)
		c.String(http.StatusInternalServerError, "Error reading certificate")
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

func isValidFileName(fileName string) bool {
	if fileName == "" || filepath.Base(fileName) != fileName {
		return false
	}
	if strings.Contains(fileName, "..") || strings.ContainsAny(fileName, `/\`) {
		return false
	}
	ext := strings.ToLower(filepath.Ext(fileName))
	return ext == ".pem" || ext == ".crt"
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
	certKey, err := rsa.GenerateKey(rand.Reader, 4096)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to generate private key"})
		return
	}

	serialNumber, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		log.Printf("Failed to generate serial number: %v", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to generate serial number"})
		return
	}

	// Create certificate template
	template := x509.Certificate{
		SerialNumber:          serialNumber,
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
	debugLog("Loaded %d DNS Names from settings", len(settingsDnsNames))
	// Append DNS names from settings
	for _, dns := range settingsDnsNames {
		if dns != "" {
			template.DNSNames = append(template.DNSNames, dns)
		}
	}

	// Append IP addresses from settings
	settingsIpAddresses := viper.GetStringSlice("certificate_manager_certificate.ip_addresses")
	debugLog("Loaded %d IP Addresses from settings", len(settingsIpAddresses))
	for _, ip := range settingsIpAddresses {
		if parsedIP := net.ParseIP(ip); parsedIP != nil {
			template.IPAddresses = append(template.IPAddresses, parsedIP)
		} else {
			debugLog("Invalid IP address format: %s", ip)
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

	// Save new private key with restricted permissions
	keyFile, err := createFileWithPermissions("data/certmanager-cert/homelab_certificate_manager.key", 0600)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to save private key"})
		return
	}
	defer keyFile.Close()
	pem.Encode(keyFile, &pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(certKey)})

	// Save new certificate with standard read permissions
	certFile, err := createFileWithPermissions("data/certmanager-cert/homelab_certificate_manager.pem", 0644)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to save certificate"})
		return
	}
	defer certFile.Close()
	pem.Encode(certFile, &pem.Block{Type: "CERTIFICATE", Bytes: certBytes})

	c.JSON(http.StatusOK, gin.H{"message": "Certificate recreated successfully"})
}

// SignCSR parses a PEM-encoded Certificate Signing Request (CSR), validates its signature,
// and signs a new certificate using the Homelab Root CA. The resulting certificate is saved as a .crt file.
func SignCSR(csrPEM []byte, validDays int) error {
	block, _ := pem.Decode(csrPEM)
	if block == nil {
		return fmt.Errorf("failed to parse PEM block: no valid PEM data found")
	}

	csr, err := x509.ParseCertificateRequest(block.Bytes)
	if err != nil {
		return fmt.Errorf("failed to parse certificate request: %w", err)
	}

	if err := csr.CheckSignature(); err != nil {
		return fmt.Errorf("invalid CSR signature: %w", err)
	}

	rootCert, rootKey, err := loadRootCertAndKey()
	if err != nil {
		return fmt.Errorf("failed to load Root CA: %w", err)
	}

	commonName := strings.TrimSpace(csr.Subject.CommonName)
	if commonName == "" {
		if len(csr.DNSNames) > 0 {
			commonName = csr.DNSNames[0]
		} else if len(csr.IPAddresses) > 0 {
			commonName = csr.IPAddresses[0].String()
		} else {
			return fmt.Errorf("CSR does not specify a CommonName or SAN")
		}
	}

	safeName := sanitizeFilename(commonName)
	if safeName == "" {
		return fmt.Errorf("invalid CommonName in CSR")
	}

	if validDays <= 0 {
		validDays = 365
	}

	serialNumber, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return fmt.Errorf("failed to generate serial number: %w", err)
	}

	subject := csr.Subject
	if subject.CommonName == "" {
		subject.CommonName = commonName
	}

	certTemplate := &x509.Certificate{
		SerialNumber:          serialNumber,
		Subject:               subject,
		NotBefore:             time.Now(),
		NotAfter:              time.Now().AddDate(0, 0, validDays),
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth},
		BasicConstraintsValid: true,
		DNSNames:              csr.DNSNames,
		IPAddresses:           csr.IPAddresses,
		EmailAddresses:        csr.EmailAddresses,
		URIs:                  csr.URIs,
		ExtraExtensions:       csr.ExtraExtensions,
	}

	certBytes, err := x509.CreateCertificate(rand.Reader, certTemplate, rootCert, csr.PublicKey, rootKey)
	if err != nil {
		return fmt.Errorf("failed to create certificate: %w", err)
	}

	if err := os.MkdirAll(filepath.Join("data", "certs"), 0755); err != nil {
		return fmt.Errorf("failed to create certs directory: %w", err)
	}

	certFilePath := filepath.Join("data", "certs", safeName+".crt")
	certFile, err := createFileWithPermissions(certFilePath, 0644)
	if err != nil {
		return fmt.Errorf("failed to save certificate file: %w", err)
	}
	defer certFile.Close()

	if err := pem.Encode(certFile, &pem.Block{Type: "CERTIFICATE", Bytes: certBytes}); err != nil {
		return fmt.Errorf("failed to encode certificate: %w", err)
	}

	return nil
}

