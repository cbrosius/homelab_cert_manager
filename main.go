package main

import (
	"log"
	"net/http"
	"os"
	"path/filepath"

	"github.com/gin-gonic/gin"
)

func main() {
	os.MkdirAll("certs", os.ModePerm)
	os.MkdirAll("root-cert", os.ModePerm) // Ensure the root-cert directory exists

	// Check if any .pem file exists in the root-cert directory
	rootCertExists := false
	err := filepath.Walk("root-cert", func(path string, info os.FileInfo, err error) error {
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
		log.Println("Root certificate already exists.")
	} else {
		log.Println("Root certificate not found.")
	}

	r := gin.Default()

	r.LoadHTMLGlob("templates/*")

	r.GET("/", showHomePage)
	r.GET("/certificates", checkRootCertAndListCerts) // Ensure this route calls the correct function
	r.GET("/certificates/download/:filename", downloadCertificate)
	r.GET("/certificates/view/:filename", viewCertificate)
	r.POST("/certificates/delete/:filename", deleteCertificate)
	r.POST("/create-certificate", createCertificate)
	r.POST("/create-root-certificate", createRootCertificate)
	r.GET("/create-certificate-form", showCreateCertificateForm)                 // Route for certificate form
	r.GET("/certificates/download/root-cert/:filename", downloadRootCertificate) // Route for downloading root certificate
	r.POST("/certificates/delete/root-cert/:filename", deleteRootCertificate)    // Route for deleting root certificate

	r.Run(":8080")
}

func showHomePage(c *gin.Context) {
	// Check if any .pem file exists in the root-cert directory
	rootCertExists := false
	err := filepath.Walk("root-cert", func(path string, info os.FileInfo, err error) error {
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

	c.HTML(http.StatusOK, "index.html", gin.H{
		"rootExists": rootCertExists,
	})
}

func showCreateCertificateForm(c *gin.Context) {
	c.HTML(http.StatusOK, "create_certificate.html", nil)
}
