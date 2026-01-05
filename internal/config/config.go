package config

import (
	"os"
)

// Config holds all configuration for the SSH CA
type Config struct {
	BindAddr string
	DBPath   string
	KeyPath  string
	Mode     string // "online" or "offline"
	// Security configuration
	PKCS11            PKCS11Config `json:"pkcs11"`
	HardenedTrustSync bool         `json:"hardened_trust_sync"`
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

	return &Config{
		BindAddr:          bindAddr,
		DBPath:            dbPath,
		KeyPath:           keyPath,
		Mode:              mode,
		HardenedTrustSync: hardened,
	}, nil
}
