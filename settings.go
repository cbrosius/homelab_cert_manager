package main

import (
	"os"
	"strings"

	"github.com/spf13/viper"
)

type Settings struct {
	CertManagerCertificate struct {
		DnsNames    []string `mapstructure:"dns_names"`
		IpAddresses []string `mapstructure:"ip_addresses"`
	} `mapstructure:"certificate_manager_certificate"`

	GeneralCertOptions struct {
		ValidityPeriod   string `mapstructure:"validity_period"`
		Organization     string `mapstructure:"organization"`
		OrganizationUnit string `mapstructure:"organization_unit"`
		Country          string `mapstructure:"country"`
		State            string `mapstructure:"state"`
		Location         string `mapstructure:"location"`
		Email            string `mapstructure:"email"`
	} `mapstructure:"general_cert_options"`

	SessionSettings struct {
		TimeoutMinutes int `mapstructure:"timeout_minutes"`
	} `mapstructure:"session_settings"`
}

func initSettings() error {
	debugLog("initSettings called")
	viper.SetConfigName("settings")
	viper.SetConfigType("json")
	viper.AddConfigPath("data")

	// Set defaults
	viper.SetDefault("certificate_manager_certificate.dns_names", []string{})
	viper.SetDefault("certificate_manager_certificate.ip_addresses", []string{})

	viper.SetDefault("general_cert_options.validity_period", "10")
	viper.SetDefault("general_cert_options.organization", "")
	viper.SetDefault("general_cert_options.organization_unit", "")
	viper.SetDefault("general_cert_options.country", "")
	viper.SetDefault("general_cert_options.state", "")
	viper.SetDefault("general_cert_options.location", "")
	viper.SetDefault("general_cert_options.email", "")

	viper.SetDefault("session_settings.timeout_minutes", 2)

	if err := viper.ReadInConfig(); err != nil {
		if _, ok := err.(viper.ConfigFileNotFoundError); ok {
			return viper.SafeWriteConfig()
		}
		return err
	}
	return nil
}

// getSessionTimeoutMinutes returns the configured session timeout between 1 and 30 minutes (default 2).
func getSessionTimeoutMinutes() int {
	mins := viper.GetInt("session_settings.timeout_minutes")
	if mins < 1 || mins > 30 {
		return 2
	}
	return mins
}

// saveViperConfig persists the viper configuration and ensures restricted 0600 file permissions.
func saveViperConfig() error {
	configFile := viper.ConfigFileUsed()
	if configFile == "" {
		configFile = "data/settings.json"
	}
	err := viper.WriteConfig()
	if err != nil {
		err = viper.WriteConfigAs(configFile)
	}
	if err != nil {
		return err
	}
	_ = os.Chmod(configFile, 0600)
	return nil
}

// saveSessionSettings saves the session timeout setting after validation.
func saveSessionSettings(timeoutMinutes int) error {
	debugLog("saveSessionSettings called with %d", timeoutMinutes)
	if err := validateSessionTimeout(timeoutMinutes); err != nil {
		return err
	}
	viper.Set("session_settings.timeout_minutes", timeoutMinutes)
	return saveViperConfig()
}

func saveCertManagerSettings(dnsNames []string, ipAddresses []string) error {
	debugLog("saveCertManagerSettings called")
	// Strip leading and trailing spaces from DNS names
	for i, dns := range dnsNames {
		dnsNames[i] = strings.TrimSpace(dns)
	}

	// Strip leading and trailing spaces from IP addresses
	for i, ip := range ipAddresses {
		ipAddresses[i] = strings.TrimSpace(ip)
	}

	viper.Set("certificate_manager_certificate.dns_names", dnsNames)
	viper.Set("certificate_manager_certificate.ip_addresses", ipAddresses)
	return saveViperConfig()
}

func saveGeneralCertOptions(validityPeriod, organization, organizationUnit, country, state, location, email string) error {
	debugLog("saveGeneralCertOptions called")
	viper.Set("general_cert_options.validity_period", strings.TrimSpace(validityPeriod))
	viper.Set("general_cert_options.organization", strings.TrimSpace(organization))
	viper.Set("general_cert_options.organization_unit", strings.TrimSpace(organizationUnit))
	viper.Set("general_cert_options.country", strings.TrimSpace(country))
	viper.Set("general_cert_options.state", strings.TrimSpace(state))
	viper.Set("general_cert_options.location", strings.TrimSpace(location))
	viper.Set("general_cert_options.email", strings.TrimSpace(email))
	return saveViperConfig()
}
