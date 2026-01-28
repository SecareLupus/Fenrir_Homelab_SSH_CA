/*
 * Copyright (c) 2026 SecareLupus
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 */

package config

import (
	"os"
)

// Version is injected at build time
var Version = "dev"

// Config holds all configuration for the SSH CA
type Config struct {
	BindAddr string
	DBPath   string
	KeyPath  string
	Mode     string // "online" or "offline"
	// Security configuration
	PKCS11            PKCS11Config   `json:"pkcs11"`
	HardenedTrustSync bool           `json:"hardened_trust_sync"`
	OIDC              OIDCConfig     `json:"oidc"`
	WebAuthn          WebAuthnConfig `json:"webauthn"`
	AuditWebhookURL   string         `json:"audit_webhook_url"`
	CAPassphrase      string         `json:"ca_passphrase"`
	DBEncryptionKey   string         `json:"db_encryption_key"`
	SessionSecret     string         `json:"session_secret"`
}

type OIDCConfig struct {
	Enabled      bool   `json:"enabled"`
	IssuerURL    string `json:"issuer_url"`
	ClientID     string `json:"client_id"`
	ClientSecret string `json:"client_secret"`
	RedirectURL  string `json:"redirect_url"`
}

type WebAuthnConfig struct {
	RPDisplayName string `json:"rp_display_name"`
	RPID          string `json:"rp_id"`
	RPOrigin      string `json:"rp_origin"`
}

type PKCS11Config struct {
	Enabled    bool   `json:"enabled"`
	Module     string `json:"module"`
	TokenLabel string `json:"token_label"`
	PIN        string `json:"pin"`
	KeyLabel   string `json:"key_label"`
}

// Load reads configuration from environment variables or defaults
func Load() (*Config, error) {
	mode := os.Getenv("CA_MODE")
	if mode == "" {
		mode = "online"
	}

	bindAddr := os.Getenv("BIND_ADDR")
	if bindAddr == "" {
		bindAddr = ":8080"
	}

	dbPath := os.Getenv("DB_PATH")
	if dbPath == "" {
		dbPath = "ssh-ca.db"
	}

	keyPath := os.Getenv("KEY_PATH")
	if keyPath == "" {
		keyPath = "ca-keys"
	}

	hardened := os.Getenv("CA_HARDENED_SYNC") == "true"

	oidcEnabled := os.Getenv("OIDC_ENABLED") == "true"
	oidcIssuer := os.Getenv("OIDC_ISSUER_URL")
	oidcClientID := os.Getenv("OIDC_CLIENT_ID")
	oidcSecret := os.Getenv("OIDC_CLIENT_SECRET")
	oidcRedirect := os.Getenv("OIDC_REDIRECT_URL")
	caPassphrase := os.Getenv("CA_PASSPHRASE")
	dbEncKey := os.Getenv("DB_ENCRYPTION_KEY")
	webhookURL := os.Getenv("AUDIT_WEBHOOK_URL")
	sessionSecret := os.Getenv("SESSION_SECRET")

	rpName := os.Getenv("WEBAUTHN_RP_DISPLAY_NAME")
	if rpName == "" {
		rpName = "Homelab SSH CA"
	}
	rpID := os.Getenv("WEBAUTHN_RP_ID")
	if rpID == "" {
		rpID = "localhost"
	}
	rpOrigin := os.Getenv("WEBAUTHN_RP_ORIGIN")
	if rpOrigin == "" {
		rpOrigin = "http://localhost:8080"
	}

	return &Config{
		BindAddr:          bindAddr,
		DBPath:            dbPath,
		KeyPath:           keyPath,
		Mode:              mode,
		HardenedTrustSync: hardened,
		OIDC: OIDCConfig{
			Enabled:      oidcEnabled,
			IssuerURL:    oidcIssuer,
			ClientID:     oidcClientID,
			ClientSecret: oidcSecret,
			RedirectURL:  oidcRedirect,
		},
		WebAuthn: WebAuthnConfig{
			RPDisplayName: rpName,
			RPID:          rpID,
			RPOrigin:      rpOrigin,
		},
		AuditWebhookURL: webhookURL,
		CAPassphrase:    caPassphrase,
		DBEncryptionKey: dbEncKey,
		SessionSecret:   sessionSecret,
	}, nil
}
