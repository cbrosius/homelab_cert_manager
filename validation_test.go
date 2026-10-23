package main

import (
	"testing"
)

func TestValidateCommonName(t *testing.T) {
	tests := []struct {
		name    string
		cn      string
		wantErr bool
	}{
		{"Valid CN", "homelab.local", false},
		{"Valid with spaces", "HomeLab Root CA", false},
		{"Empty string", "", true},
		{"Only whitespace", "   ", true},
		{"Exactly 64 chars", "1234567890123456789012345678901234567890123456789012345678901234", false},
		{"Exceeds 64 chars", "12345678901234567890123456789012345678901234567890123456789012345", true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := validateCommonName(tt.cn)
			if (err != nil) != tt.wantErr {
				t.Errorf("validateCommonName(%q) error = %v, wantErr %v", tt.cn, err, tt.wantErr)
			}
		})
	}
}

func TestValidateValidityYears(t *testing.T) {
	tests := []struct {
		name      string
		val       string
		minYears  int
		maxYears  int
		wantYears int
		wantErr   bool
	}{
		{"Valid 10 years", "10", 1, 30, 10, false},
		{"Valid 1 year", "1", 1, 10, 1, false},
		{"Valid 30 years", "30", 1, 30, 30, false},
		{"Zero years", "0", 1, 30, 0, true},
		{"Negative years", "-5", 1, 30, 0, true},
		{"Exceeds max", "50", 1, 30, 0, true},
		{"Non-numeric", "abc", 1, 30, 0, true},
		{"Empty string", "", 1, 30, 0, true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			years, err := validateValidityYears(tt.val, tt.minYears, tt.maxYears)
			if (err != nil) != tt.wantErr {
				t.Errorf("validateValidityYears(%q) error = %v, wantErr %v", tt.val, err, tt.wantErr)
			}
			if !tt.wantErr && years != tt.wantYears {
				t.Errorf("validateValidityYears(%q) = %d, want %d", tt.val, years, tt.wantYears)
			}
		})
	}
}

func TestValidateEmail(t *testing.T) {
	tests := []struct {
		name    string
		email   string
		wantErr bool
	}{
		{"Empty email allowed", "", false},
		{"Valid email", "admin@homelab.local", false},
		{"Valid public email", "admin@example.com", false},
		{"Missing @", "adminexample.com", true},
		{"Missing domain dot", "admin@localhost", true},
		{"Whitespace only", "   ", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := validateEmail(tt.email)
			if (err != nil) != tt.wantErr {
				t.Errorf("validateEmail(%q) error = %v, wantErr %v", tt.email, err, tt.wantErr)
			}
		})
	}
}

func TestValidateCountry(t *testing.T) {
	tests := []struct {
		name    string
		country string
		wantErr bool
	}{
		{"Empty country allowed", "", false},
		{"Valid 2-letter ISO (DE)", "DE", false},
		{"Valid 2-letter ISO (US)", "US", false},
		{"3 letters", "USA", true},
		{"1 letter", "U", true},
		{"Long placeholder string", "<YOUR COUNTRY>", true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := validateCountry(tt.country)
			if (err != nil) != tt.wantErr {
				t.Errorf("validateCountry(%q) error = %v, wantErr %v", tt.country, err, tt.wantErr)
			}
		})
	}
}

func TestValidateDNSName(t *testing.T) {
	tests := []struct {
		name    string
		dns     string
		wantErr bool
	}{
		{"Empty string allowed", "", false},
		{"Single label hostname", "proxmox", false},
		{"Single label nas", "nas", false},
		{"FQDN", "router.homelab.local", false},
		{"Wildcard domain", "*.homelab.local", false},
		{"Contains invalid characters", "server name", true},
		{"Leading hyphen", "-server.local", true},
		{"Trailing hyphen label", "server-.local", true},
		{"Double dot", "server..local", true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := validateDNSName(tt.dns)
			if (err != nil) != tt.wantErr {
				t.Errorf("validateDNSName(%q) error = %v, wantErr %v", tt.dns, err, tt.wantErr)
			}
		})
	}
}

func TestValidateIPAddress(t *testing.T) {
	tests := []struct {
		name    string
		ip      string
		wantErr bool
	}{
		{"Empty IP allowed", "", false},
		{"Valid IPv4", "192.168.1.1", false},
		{"Valid IPv4 10.x", "10.0.0.50", false},
		{"Valid IPv6 loopback", "::1", false},
		{"Valid IPv6 full", "fe80::1", false},
		{"Invalid IPv4 octet", "192.168.1.300", true},
		{"Invalid format string", "not-an-ip", true},
		{"Incomplete IPv4", "192.168.1", true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := validateIPAddress(tt.ip)
			if (err != nil) != tt.wantErr {
				t.Errorf("validateIPAddress(%q) error = %v, wantErr %v", tt.ip, err, tt.wantErr)
			}
		})
	}
}

func TestValidatePassword(t *testing.T) {
	tests := []struct {
		name        string
		newPassword string
		oldPassword string
		wantErr     bool
	}{
		{"Valid password", "CorrectHorseBatteryStaple123", "OldSecretPassword1", false},
		{"Exactly 8 characters", "12345678", "OldSecretPassword1", false},
		{"Too short (7 chars)", "1234567", "OldSecretPassword1", true},
		{"Empty password", "", "OldSecretPassword1", true},
		{"Only whitespace", "        ", "OldSecretPassword1", true},
		{"Cannot be admin", "admin", "OldSecretPassword1", true},
		{"Cannot be Admin (case insensitive)", "Admin", "OldSecretPassword1", true},
		{"Cannot be same as old password", "SamePassword123", "SamePassword123", true},
		{"Exceeds 72 chars", "1234567890123456789012345678901234567890123456789012345678901234567890123", "OldSecretPassword1", true},
		{"Exactly 72 chars", "123456789012345678901234567890123456789012345678901234567890123456789012", "OldSecretPassword1", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := validatePassword(tt.newPassword, tt.oldPassword)
			if (err != nil) != tt.wantErr {
				t.Errorf("validatePassword(%q, %q) error = %v, wantErr %v", tt.newPassword, tt.oldPassword, err, tt.wantErr)
			}
		})
	}
}

func TestValidateSessionTimeout(t *testing.T) {
	tests := []struct {
		name    string
		minutes int
		wantErr bool
	}{
		{"Valid 1 minute", 1, false},
		{"Valid 15 minutes", 15, false},
		{"Valid 30 minutes", 30, false},
		{"Zero minutes (too short)", 0, true},
		{"Negative minutes", -5, true},
		{"31 minutes (too long)", 31, true},
		{"60 minutes (too long)", 60, true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := validateSessionTimeout(tt.minutes)
			if (err != nil) != tt.wantErr {
				t.Errorf("validateSessionTimeout(%d) error = %v, wantErr %v", tt.minutes, err, tt.wantErr)
			}
		})
	}
}

