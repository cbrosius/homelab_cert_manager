package main

import (
	"github.com/spf13/viper"
)

type Settings struct {
	CertManagerCertificate struct {
		DnsNames    []string `mapstructure:"dns_names"`
		IpAddresses []string `mapstructure:"ip_addresses"`
	} `mapstructure:"certificate_manager_certificate"`
}

func initSettings() error {
	viper.SetConfigName("settings")
	viper.SetConfigType("json")
	viper.AddConfigPath("data")

	// Set defaults
	viper.SetDefault("certificate_manager_certificate.dns_names", []string{})
	viper.SetDefault("certificate_manager_certificate.ip_addresses", []string{})

	if err := viper.ReadInConfig(); err != nil {
		if _, ok := err.(viper.ConfigFileNotFoundError); ok {
			return viper.SafeWriteConfig()
		}
		return err
	}
	return nil
}

func saveCertManagerSettings(dnsNames []string, ipAddresses []string) error {
	viper.Set("certificate_manager_certificate.dns_names", dnsNames)
	viper.Set("certificate_manager_certificate.ip_addresses", ipAddresses)
	return viper.WriteConfig()
}
