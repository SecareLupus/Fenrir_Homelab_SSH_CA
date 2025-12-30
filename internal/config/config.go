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

	return &Config{
		BindAddr: bindAddr,
		DBPath:   dbPath,
		KeyPath:  keyPath,
		Mode:     mode,
	}, nil
}
