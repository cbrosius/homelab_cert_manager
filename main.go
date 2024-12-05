package main

import (
	"crypto/rand"
	"log"
	"net/http"
	"os"
	"path/filepath"

	"github.com/gin-contrib/sessions"
	"github.com/gin-contrib/sessions/cookie"
	"github.com/gin-gonic/gin"
)

const (
	userKey         = "user"
	defaultUsername = "admin"
	defaultPassword = "admin123" // In production, use a secure password and store it hashed
)

func main() {
	os.MkdirAll("data/certs", os.ModePerm)
	os.MkdirAll("data/root-cert", os.ModePerm) // Ensure the root-cert directory exists

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
		log.Printf("Error checking root-cert directory: %v", err)
	} else if rootCertExists {
		log.Println("Root certificate already exists.")
	} else {
		log.Println("Root certificate not found.")
	}

	r := gin.Default()

	// Add these two lines
	r.Static("/static", "./static")
	r.LoadHTMLGlob("templates/*")

	// Generate a random 32-byte key for cookie store
	key := make([]byte, 32)
	if _, err := rand.Read(key); err != nil {
		log.Fatal("Failed to generate session key:", err)
	}
	store := cookie.NewStore(key)
	r.Use(sessions.Sessions("homelab_session", store))

	// Public routes
	r.GET("/login", showLoginPage)
	r.POST("/login", handleLogin)

	// Protected routes group
	authorized := r.Group("/")
	authorized.Use(authRequired())
	{
		authorized.GET("/", showHomePage)
		authorized.GET("/certificates", checkRootCertAndListCerts)
		authorized.GET("/certificates/download/:filename", downloadCertificate)
		authorized.GET("/certificates/view/:filename", viewCertificate)
		authorized.POST("/certificates/delete/:filename", deleteCertificate)
		authorized.POST("/create-certificate", createCertificate)
		authorized.POST("/create-root-certificate", createRootCertificate)
		authorized.GET("/create-certificate-form", showCreateCertificateForm)
		authorized.GET("/certificates/download/root-cert/:filename", downloadRootCertificate)
		authorized.POST("/certificates/delete/root-cert/:filename", deleteRootCertificate)
		authorized.GET("/settings", showSettingsPage)
		authorized.GET("/logout", handleLogout)
	}

	r.Run(":8085")
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

	c.HTML(http.StatusOK, "index.html", gin.H{
		"rootExists": rootCertExists,
	})
}

func showCreateCertificateForm(c *gin.Context) {
	c.HTML(http.StatusOK, "create_certificate.html", nil)
}

func showSettingsPage(c *gin.Context) {
	c.HTML(http.StatusOK, "settings.html", nil)
}

// Authentication middleware
func authRequired() gin.HandlerFunc {
	return func(c *gin.Context) {
		session := sessions.Default(c)
		user := session.Get(userKey)
		if user == nil {
			c.Redirect(http.StatusSeeOther, "/login")
			c.Abort()
			return
		}
		c.Next()
	}
}

// Login page handler
func showLoginPage(c *gin.Context) {
	session := sessions.Default(c)
	user := session.Get(userKey)
	if user != nil {
		c.Redirect(http.StatusSeeOther, "/")
		return
	}
	c.HTML(http.StatusOK, "login.html", gin.H{
		"error": session.Flashes("error"),
	})
}

// Login handler
func handleLogin(c *gin.Context) {
	session := sessions.Default(c)
	username := c.PostForm("username")
	password := c.PostForm("password")

	// In production, use proper password hashing and database storage
	if username == defaultUsername && password == defaultPassword {
		session.Set(userKey, username)
		if err := session.Save(); err != nil {
			c.HTML(http.StatusInternalServerError, "login.html", gin.H{
				"error": "Failed to save session",
			})
			return
		}
		c.Redirect(http.StatusSeeOther, "/")
		return
	}

	session.AddFlash("Invalid credentials", "error")
	session.Save()
	c.Redirect(http.StatusSeeOther, "/login")
}

// Logout handler
func handleLogout(c *gin.Context) {
	session := sessions.Default(c)
	session.Delete(userKey)
	session.Save()
	c.Redirect(http.StatusSeeOther, "/login")
}
