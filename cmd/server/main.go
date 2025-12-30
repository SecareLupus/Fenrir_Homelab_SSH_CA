package main

import (
	"log"
	"os"

	"ssh-ca/internal/config"
	"ssh-ca/internal/db"
	"ssh-ca/internal/ca"
	"ssh-ca/internal/web"
)

func main() {
	// 1. Load Configuration
	cfg, err := config.Load()
	if err != nil {
		log.Fatalf("Failed to load config: %v", err)
	}

	// 2. Initialize Database (SQLite)
	database, err := db.Init(cfg.DBPath)
	if err != nil {
		log.Fatalf("Failed to initialize database: %v", err)
	}
	defer database.Close()

	// 3. Initialize CA Service
	caService, err := ca.New(cfg.KeyPath)
	if err != nil {
		log.Fatalf("Failed to initialize CA: %v", err)
	}

	// 4. Initialize Web Server
	server := web.NewServer(cfg, database, caService)

	// 5. Start Server
	log.Printf("Starting SSH CA on %s", cfg.BindAddr)
	if err := server.Start(); err != nil {
		log.Printf("Server error: %v", err)
		os.Exit(1)
	}
}
