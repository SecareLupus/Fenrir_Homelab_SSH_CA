/*
 * Copyright (c) 2026 SecareLupus
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 */

package main

import (
	"flag"
	"fmt"
	"log"
	"os"

	 "github.com/SecareLupus/Fenrir/internal/ca"
	 "github.com/SecareLupus/Fenrir/internal/config"
	 "github.com/SecareLupus/Fenrir/internal/db"
	 "github.com/SecareLupus/Fenrir/internal/web"
)

func main() {
	showVersion := flag.Bool("version", false, "Show version and exit")
	flag.Parse()

	if *showVersion {
		fmt.Printf("SSH CA Server %s\n", config.Version)
		return
	}

	// 1. Load Configuration
	cfg, err := config.Load()
	if err != nil {
		log.Fatalf("Failed to load config: %v", err)
	}

	// 2. Initialize Database (SQLite)
	database, err := db.Init(cfg.DBPath, cfg.AuditWebhookURL, cfg.DBEncryptionKey)
	if err != nil {
		log.Fatalf("Failed to initialize database: %v", err)
	}
	defer database.Close()

	// 3. Initialize CA Service
	caService, err := ca.New(cfg)
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
