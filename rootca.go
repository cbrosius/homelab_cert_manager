package main

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"os"
	"time"

	"software.sslmate.com/src/go-pkcs12"
)

func generateRootCA() error {
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return err
	}

	rootCertTemplate := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			Organization: []string{"Your Organization"},
		},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().AddDate(10, 0, 0),
		IsCA:                  true,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
	}

	rootCertBytes, err := x509.CreateCertificate(rand.Reader, rootCertTemplate, rootCertTemplate, &privateKey.PublicKey, privateKey)
	if err != nil {
		return err
	}

	os.MkdirAll("certs", os.ModePerm)

	rootCertFile, err := os.Create("certs/rootCA.pem")
	if err != nil {
		return err
	}
	defer rootCertFile.Close()

	pem.Encode(rootCertFile, &pem.Block{Type: "CERTIFICATE", Bytes: rootCertBytes})

	rootKeyFile, err := os.Create("certs/rootCA.key")
	if err != nil {
		return err
	}
	defer rootKeyFile.Close()

	pem.Encode(rootKeyFile, &pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(privateKey)})

	// Generate .pfx file for root certificate
	rootCert, err := x509.ParseCertificate(rootCertBytes)
	if err != nil {
		return err
	}

	rootPfxData, err := pkcs12.Encode(rand.Reader, privateKey, rootCert, nil, "")
	if err != nil {
		return err
	}

	rootPfxFile, err := os.Create("certs/rootCA.pfx")
	if err != nil {
		return err
	}
	defer rootPfxFile.Close()

	rootPfxFile.Write(rootPfxData)

	return nil
}
