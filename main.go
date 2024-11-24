package main

import (
	"log"
	"net/http"
	"os"

	"github.com/gin-gonic/gin"
)

func main() {
	os.MkdirAll("certs", os.ModePerm)

	if _, err := os.Stat("certs/rootCA.pem"); os.IsNotExist(err) {
		log.Println("Root certificate not found.")
	} else {
		log.Println("Root certificate already exists.")
	}

	r := gin.Default()

	r.LoadHTMLGlob("templates/*")

	r.GET("/", showHomePage)
	r.GET("/certificates", listCertificates)
	r.GET("/certificates/download/:filename", downloadCertificate)
	r.GET("/certificates/view/:filename", viewCertificate)
	r.POST("/certificates/delete/:filename", deleteCertificate)
	r.POST("/create-certificate", createCertificate)
	r.POST("/create-root-certificate", createRootCertificate)    // Ensure the route for creating root certificate
	r.GET("/create-certificate-form", showCreateCertificateForm) // Route for certificate form

	r.Run(":8080")
}

func showHomePage(c *gin.Context) {
	_, err := os.Stat("certs/rootCA.pem")
	rootExists := !os.IsNotExist(err)

	if rootExists {
		c.Redirect(http.StatusSeeOther, "/certificates")
		return
	}

	c.HTML(http.StatusOK, "index.html", gin.H{
		"rootExists": rootExists,
	})
}

func showCreateCertificateForm(c *gin.Context) {
	c.HTML(http.StatusOK, "create_certificate.html", nil)
}
