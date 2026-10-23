package main

import (
	"fmt"
	"net"
	"net/mail"
	"regexp"
	"strconv"
	"strings"
)

// dnsRegex allows RFC 1123 compliant single-label hostnames, FQDNs, and wildcard domains (*.example.com).
var dnsRegex = regexp.MustCompile(`^(\*\.)?([a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)*[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?$`)

// validateCommonName ensures the CN is non-empty and does not exceed RFC 5280 64-char limit.
func validateCommonName(cn string) error {
	cn = strings.TrimSpace(cn)
	if cn == "" {
		return fmt.Errorf("Common Name cannot be empty")
	}
	if len(cn) > 64 {
		return fmt.Errorf("Common Name exceeds maximum length of 64 characters")
	}
	return nil
}

// validateValidityYears checks that the string represents an integer between minYears and maxYears.
func validateValidityYears(val string, minYears, maxYears int) (int, error) {
	val = strings.TrimSpace(val)
	if val == "" {
		return 0, fmt.Errorf("validity period is required")
	}
	years, err := strconv.Atoi(val)
	if err != nil {
		return 0, fmt.Errorf("validity period must be a valid number")
	}
	if years < minYears || years > maxYears {
		return 0, fmt.Errorf("validity period must be between %d and %d years", minYears, maxYears)
	}
	return years, nil
}

// validateEmail validates an optional email address format.
func validateEmail(email string) error {
	email = strings.TrimSpace(email)
	if email == "" {
		return nil
	}
	_, err := mail.ParseAddress(email)
	if err != nil || !strings.Contains(email, "@") || !strings.Contains(email, ".") {
		return fmt.Errorf("invalid email address format: %s", email)
	}
	return nil
}

// validateCountry validates an optional 2-letter ISO country code.
func validateCountry(country string) error {
	country = strings.TrimSpace(country)
	if country == "" {
		return nil
	}
	if len(country) != 2 {
		return fmt.Errorf("country code must be a 2-letter ISO code (e.g. US, DE)")
	}
	return nil
}

// validateDNSName checks that a DNS hostname complies with DNS syntax.
func validateDNSName(dns string) error {
	dns = strings.TrimSpace(dns)
	if dns == "" {
		return nil
	}
	if len(dns) > 253 {
		return fmt.Errorf("DNS name exceeds maximum length of 253 characters: %s", dns)
	}
	if !dnsRegex.MatchString(dns) {
		return fmt.Errorf("invalid DNS name syntax: %s", dns)
	}
	return nil
}

// validateIPAddress parses and validates an IPv4 or IPv6 address string.
func validateIPAddress(ipStr string) (net.IP, error) {
	ipStr = strings.TrimSpace(ipStr)
	if ipStr == "" {
		return nil, nil
	}
	ip := net.ParseIP(ipStr)
	if ip == nil {
		return nil, fmt.Errorf("invalid IP address format: %s", ipStr)
	}
	return ip, nil
}

// validatePassword checks that the new password meets security requirements:
// minimum 8 characters, maximum 72 characters (bcrypt limit), not empty/whitespace,
// not the default "admin", and different from the current password.
func validatePassword(newPassword, oldPassword string) error {
	trimmed := strings.TrimSpace(newPassword)
	if len(newPassword) < 8 {
		return fmt.Errorf("password must be at least 8 characters long")
	}
	if len(newPassword) > 72 {
		return fmt.Errorf("password cannot exceed 72 characters")
	}
	if trimmed == "" {
		return fmt.Errorf("password cannot be empty or only whitespace")
	}
	if strings.ToLower(newPassword) == "admin" {
		return fmt.Errorf("password cannot be 'admin'")
	}
	if oldPassword != "" && newPassword == oldPassword {
		return fmt.Errorf("new password must be different from the old password")
	}
	return nil
}
