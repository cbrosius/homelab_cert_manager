package main

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"html/template"
	"log"
	"math/big"
	"net/http"
	"os"
	"path/filepath"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/spf13/viper"
)

// toJson converts a Go data structure to a JSON string
func toJson(v interface{}) (string, error) {
	bytes, err := json.Marshal(v)
	if err != nil {
		return "", err
	}
	return string(bytes), nil
}

// type CertManagerSettings struct {
// 	DnsNames    []string `json:"dns_names"`
// 	IpAddresses []string `json:"ip_addresses"`
// }

// type generalCertOptions struct {
// 	ValidityPeriod   int    `json:"validity_period"`
// 	Organization     string `json:"organization"`
// 	OrganizationUnit string `json:"organization_unit"`
// 	Country          string `json:"country"`
// 	State            string `json:"state"`
// 	Location         string `json:"location"`
// }

func main() {
	os.MkdirAll("data/certs", os.ModePerm)
	os.MkdirAll("data/root-cert", os.ModePerm)
	os.MkdirAll("data/certmanager-cert", os.ModePerm)
	os.MkdirAll("data", os.ModePerm)

	// Initialize settings
	if err := initSettings(); err != nil {
		log.Fatalf("Failed to initialize settings: %v", err)
	}

	// First check if any .pem file exists in the certmanager-cert directory
	certManagerCertExists := false
	err := filepath.Walk("data/certmanager-cert", func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		if !info.IsDir() && filepath.Ext(info.Name()) == ".pem" {
			certManagerCertExists = true
			return filepath.SkipDir
		}
		return nil
	})

	if err != nil {
		log.Printf("Error checking certmanager-cert directory: %v", err)
	} else if certManagerCertExists {
		log.Println("Certificate Manager certificate already exists.")
	} else {
		log.Println("Certificate Manager certificate not found.")
		// Generate self-signed certificate for Certificate Manager
		certKey, err := rsa.GenerateKey(rand.Reader, 2048)
		if err != nil {
			log.Printf("Failed to generate private key: %v", err)
			return
		}

		template := x509.Certificate{
			SerialNumber: big.NewInt(1),
			Subject: pkix.Name{
				CommonName: "HomeLab Certificate Manager",
			},
			NotBefore: time.Now(),
			NotAfter:  time.Now().AddDate(10, 0, 0), // Valid for 10 years
			KeyUsage:  x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
			ExtKeyUsage: []x509.ExtKeyUsage{
				x509.ExtKeyUsageServerAuth,
			},
			BasicConstraintsValid: true,
		}

		certBytes, err := x509.CreateCertificate(rand.Reader, &template, &template, &certKey.PublicKey, certKey)
		if err != nil {
			log.Printf("Failed to create certificate: %v", err)
			return
		}

		// Save private key
		keyFile, err := os.Create("data/certmanager-cert/selfsigned.key")
		if err != nil {
			log.Printf("Failed to create key file: %v", err)
			return
		}
		defer keyFile.Close()

		err = pem.Encode(keyFile, &pem.Block{
			Type:  "RSA PRIVATE KEY",
			Bytes: x509.MarshalPKCS1PrivateKey(certKey),
		})
		if err != nil {
			log.Printf("Failed to write key file: %v", err)
			return
		}

		// Save certificate
		certFile, err := os.Create("data/certmanager-cert/selfsigned.pem")
		if err != nil {
			log.Printf("Failed to create certificate file: %v", err)
			return
		}
		defer certFile.Close()

		err = pem.Encode(certFile, &pem.Block{
			Type:  "CERTIFICATE",
			Bytes: certBytes,
		})
		if err != nil {
			log.Printf("Failed to write certificate file: %v", err)
			return
		}

		log.Println("Certificate Manager certificate generated successfully")

	}

	rootCertExists := false
	err = filepath.Walk("data/root-cert", func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		if !info.IsDir() && filepath.Ext(info.Name()) == ".pem" {
			rootCertExists = true
			return filepath.SkipDir
		}
		return nil
	})
	if err != nil {
		log.Printf("Error checking root-cert directory: %v", err)
	} else if rootCertExists {
		log.Println("Root certificate exists.")
	} else {
		log.Println("Root certificate not found.")
	}

	// Initialize Viper for settings management
	viper.SetConfigName("settings")
	viper.SetConfigType("json")
	viper.AddConfigPath("data")

	// Read the config file if it exists
	if err := viper.ReadInConfig(); err != nil {
		log.Println("No existing settings file found. A new one will be created.")
	}

	// Initialize settings
	if err := initSettings(); err != nil {
		log.Fatalf("Failed to initialize settings: %v", err)
	}

	r := gin.Default()
	r.Static("/static", "./static") // Konfiguration, um statische Dateien zu bedienen

	// Add the toJson function to the template's function map
	r.SetFuncMap(template.FuncMap{
		"toJson": toJson,
	})

	// Load templates with the function map
	r.LoadHTMLGlob("templates/*")

	r.GET("/", showHomePage)
	r.GET("/certificates", checkRootCertAndListCerts) // Ensure this route calls the correct function
	r.GET("/certificates/view/:filename", viewCertificate)
	r.POST("/certificates/delete/:filename", deleteCertificate)
	r.POST("/create-certificate", createCertificate)
	r.GET("/certificates/download/:filename", func(c *gin.Context) {
		c.Params = append(c.Params, gin.Param{Key: "certType", Value: "certs"})
		downloadCertificate(c)
	})
	r.POST("/create-root-certificate", createRootCertificate)
	r.GET("/certificates/download/root-cert/:filename", func(c *gin.Context) {
		c.Params = append(c.Params, gin.Param{Key: "certType", Value: "root-cert"})
		downloadCertificate(c)
	})
	r.GET("/create-certificate-form", showCreateCertificateForm)              // Route for certificate form
	r.POST("/certificates/delete/root-cert/:filename", deleteRootCertificate) // Route for deleting root certificate
	r.GET("/settings", showSettingsPage)                                      // Route for settings page
	// r.POST("/settings", handleSettings)                                       // Route for saving settings
	r.GET("/howto", showHowToPage) // Add this new route
	r.POST("/recreate-homelab-cert", recreateHomelabCertificate)

	r.GET("/settings/certmanager", handleCertManagerSettings)
	r.POST("/settings/certmanager", handleCertManagerSettings)

	r.GET("/settings/generalcertoptions", handleGeneralCertOptions)
	r.POST("/settings/generalcertoptions", handleGeneralCertOptions)

	// Determine which certificate to use
	selfSignedCert := filepath.Join("data", "certmanager-cert", "selfsigned.pem")
	selfSignedKey := filepath.Join("data", "certmanager-cert", "selfsigned.key")
	homelabCert := filepath.Join("data", "certmanager-cert", "homelab_certificate_manager.pem")
	homelabKey := filepath.Join("data", "certmanager-cert", "homelab_certificate_manager.key")

	var certFile, keyFile string

	if _, err := os.Stat(homelabCert); err == nil {
		certFile = homelabCert
		keyFile = homelabKey

		// Remove self-signed certificate and key if homelab certificate exists
		os.Remove(selfSignedCert)
		os.Remove(selfSignedKey)
	} else if _, err := os.Stat(selfSignedCert); err == nil {
		certFile = selfSignedCert
		keyFile = selfSignedKey
	} else {
		log.Fatal("No valid certificate found. Please generate either selfsigned.pem or homelab_certificate_manager.pem")
	}

	// Start the server with the selected certificate
	r.RunTLS(":8443", certFile, keyFile)
}

func showHomePage(c *gin.Context) {
	// Check if any .pem file exists in the root-cert directory
	rootCertExists := false
	err := filepath.Walk("data/root-cert", func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		if !info.IsDir() && filepath.Ext(info.Name()) == ".pem" {
			rootCertExists = true
			return filepath.SkipDir
		}
		return nil
	})
	if err != nil {
		c.String(http.StatusInternalServerError, "Error checking root-cert directory: %v", err)
		return
	}

	if rootCertExists {
		c.Redirect(http.StatusSeeOther, "/certificates")
		return
	}

	renderTemplate(c, "index.html", gin.H{
		"rootExists": rootCertExists,
	})
}

func showCreateCertificateForm(c *gin.Context) {
	renderTemplate(c, "create_certificate.html", nil)
}

func showSettingsPage(c *gin.Context) {
	renderTemplate(c, "settings.html", gin.H{
		"certManagerSettings": gin.H{
			"DnsNames":    viper.GetStringSlice("certificate_manager_certificate.dns_names"),
			"IpAddresses": viper.GetStringSlice("certificate_manager_certificate.ip_addresses"),
		},
		"generalCertOptions": gin.H{
			"ValidityPeriod":   viper.GetString("general_cert_options.validity_period"),
			"Organization":     viper.GetString("general_cert_options.organization"),
			"OrganizationUnit": viper.GetString("general_cert_options.organization_unit"),
			"Country":          viper.GetString("general_cert_options.country"),
			"State":            viper.GetString("general_cert_options.state"),
			"Location":         viper.GetString("general_cert_options.location"),
		},
	})
}

func showHowToPage(c *gin.Context) {
	renderTemplate(c, "howto.html", nil)
}

// func handleSettings(c *gin.Context) {
// 	var settings struct {
// 		DnsNames    []string `json:"dns_names"`
// 		IpAddresses []string `json:"ip_addresses"`
// 	}

// 	if err := c.BindJSON(&settings); err != nil {
// 		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid settings format"})
// 		return
// 	}

// 	// Save certificate manager settings
// 	if err := saveCertManagerSettings(settings.DnsNames, settings.IpAddresses); err != nil {
// 		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to save settings"})
// 		return
// 	}

// 	c.JSON(http.StatusOK, gin.H{"message": "Settings saved successfully"})
// }

func loadRootCertAndKey() (*x509.Certificate, *rsa.PrivateKey, error) {
	// Read root certificate
	certPEM, err := os.ReadFile("data/root-cert/HomeLab_Root_CA.pem")
	if err != nil {
		return nil, nil, err
	}
	block, _ := pem.Decode(certPEM)
	rootCert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return nil, nil, err
	}

	// Read root private key
	keyPEM, err := os.ReadFile("data/root-cert/HomeLab_Root_CA.key")
	if err != nil {
		return nil, nil, err
	}
	block, _ = pem.Decode(keyPEM)
	rootKey, err := x509.ParsePKCS1PrivateKey(block.Bytes)
	if err != nil {
		return nil, nil, err
	}

	return rootCert, rootKey, nil
}

func handleCertManagerSettings(c *gin.Context) {

	log.Println("running handleCertManagerSettings ...")

	if c.Request.Method == "GET" {
		c.JSON(http.StatusOK, gin.H{
			"dns_names":    viper.GetStringSlice("certificate_manager_certificate.dns_names"),
			"ip_addresses": viper.GetStringSlice("certificate_manager_certificate.ip_addresses"),
		})
		return
	}

	var certSettings struct {
		DnsNames    []string `json:"dns_names"`
		IpAddresses []string `json:"ip_addresses"`
	}
	if err := c.BindJSON(&certSettings); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	if err := saveCertManagerSettings(certSettings.DnsNames, certSettings.IpAddresses); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	c.JSON(http.StatusOK, certSettings)
}

func handleGeneralCertOptions(c *gin.Context) {
	log.Println("running handleGeneralCertOptions ...")

	if c.Request.Method == "GET" {
		c.JSON(http.StatusOK, gin.H{
			"validity_period":   viper.GetString("general_cert_options.validity_period"),
			"organization":      viper.GetString("general_cert_options.organization"),
			"organization_unit": viper.GetString("general_cert_options.organization_unit"),
			"country":           viper.GetString("general_cert_options.country"),
			"state":             viper.GetString("general_cert_options.state"),
			"location":          viper.GetString("general_cert_options.location"),
		})
		return
	}

	var generalCertOptions struct {
		ValidityPeriod   string `json:"validity_period"`
		Organization     string `json:"organization"`
		OrganizationUnit string `json:"organization_unit"`
		Country          string `json:"country"`
		State            string `json:"state"`
		Location         string `json:"location"`
	}

	if err := c.BindJSON(&generalCertOptions); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	if err := saveGeneralCertOptions(
		generalCertOptions.ValidityPeriod,
		generalCertOptions.Organization,
		generalCertOptions.OrganizationUnit,
		generalCertOptions.Country,
		generalCertOptions.State,
		generalCertOptions.Location,
	); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	c.JSON(http.StatusOK, generalCertOptions)
}

func renderTemplate(c *gin.Context, templateName string, data gin.H) {
	if data == nil {
		data = gin.H{}
	}
	c.HTML(http.StatusOK, templateName, data)
}
