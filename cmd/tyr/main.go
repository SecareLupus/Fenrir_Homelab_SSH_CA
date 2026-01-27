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
	"bytes"
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"syscall"

	"github.com/SecareLupus/Fenrir_Homelab_SSH_CA/internal/client"
	"github.com/SecareLupus/Fenrir_Homelab_SSH_CA/internal/config"
	"golang.org/x/term"
)

func main() {
	showVersion := flag.Bool("version", false, "Show version and exit")
	caURL := flag.String("url", "http://localhost:8080", "SSH CA Server URL")
	apiKeyFile := flag.String("key-file", "", "Path to file containing API Key (optional if already enrolled)")
	username := flag.String("username", "", "Username for Fenrir login (alternative to API key)")
	password := flag.String("password", "", "Password for Fenrir login (will prompt if not provided)")
	keyPath := flag.String("identity", "", "Path to SSH private key")
	keyType := flag.String("type", "ed25519", "Key type to generate (ed25519, ed25519-sk)")
	flag.Parse()

	if *showVersion {
		fmt.Printf("SSH CA Client %s\n", config.Version)
		return
	}

	var apiKey string

	// If username is provided, authenticate and get an API key
	if *username != "" {
		var pwd string
		if *password != "" {
			pwd = *password
		} else {
			fmt.Print("Password: ")
			pwdBytes, err := readPassword()
			if err != nil {
				log.Fatalf("Failed to read password: %v", err)
			}
			pwd = string(pwdBytes)
			fmt.Println()
		}

		var err error
		apiKey, err = loginAndGetAPIKey(*caURL, *username, pwd)
		if err != nil {
			log.Fatalf("Login failed: %v", err)
		}

		fmt.Println("✓ Successfully authenticated with Fenrir")
	} else if *apiKeyFile != "" {
		// Otherwise, use API key file if provided
		keyBytes, _ := os.ReadFile(*apiKeyFile)
		apiKey = string(keyBytes)
	}

	if *keyPath == "" {
		home, _ := os.UserHomeDir()
		suffix := "id_ed25519"
		if *keyType == "ed25519-sk" {
			suffix = "id_ed25519_sk"
		}
		*keyPath = filepath.Join(home, ".ssh", suffix)
	}

	cfg := &client.Config{
		CAURL:      *caURL,
		KeyPath:    *keyPath,
		KeyType:    *keyType,
		APIKey:     apiKey,
		AutoEnroll: true,
	}

	fmt.Printf("Requesting certificate for %s...\n", *keyPath)

	err := cfg.Sign(context.Background(), func(challenge string) {
		fmt.Println("PoP Challenge received. Touch your security key if prompted...")
	})

	if err != nil {
		log.Fatalf("Error: %v", err)
	}

	fmt.Println("Success! Certificate saved.")
}

// loginAndGetAPIKey authenticates with Fenrir and returns an API key
func loginAndGetAPIKey(caURL, username, password string) (string, error) {
	reqBody := map[string]string{
		"username": username,
		"password": password,
	}

	bodyBytes, _ := json.Marshal(reqBody)
	resp, err := http.Post(caURL+"/api/auth/login", "application/json", bytes.NewReader(bodyBytes))
	if err != nil {
		return "", fmt.Errorf("connection failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode == 401 {
		return "", fmt.Errorf("invalid credentials")
	}

	var respData struct {
		APIKey      string `json:"api_key"`
		MFARequired bool   `json:"mfa_required"`
		Error       string `json:"error"`
	}

	if err := json.NewDecoder(resp.Body).Decode(&respData); err != nil {
		return "", fmt.Errorf("failed to parse response: %w", err)
	}

	if respData.MFARequired {
		// Prompt for MFA code
		fmt.Print("MFA code: ")
		var mfaCode string
		fmt.Scanln(&mfaCode)

		reqBody["totp_code"] = mfaCode
		bodyBytes, _ = json.Marshal(reqBody)
		resp, err = http.Post(caURL+"/api/auth/login", "application/json", bytes.NewReader(bodyBytes))
		if err != nil {
			return "", fmt.Errorf("MFA verification failed: %w", err)
		}
		defer resp.Body.Close()

		if resp.StatusCode != 200 {
			return "", fmt.Errorf("invalid MFA code")
		}

		if err := json.NewDecoder(resp.Body).Decode(&respData); err != nil {
			return "", fmt.Errorf("failed to parse response: %w", err)
		}
	}

	if respData.Error != "" {
		return "", fmt.Errorf(respData.Error)
	}

	return respData.APIKey, nil
}

// readPassword reads a password from stdin without echoing
func readPassword() ([]byte, error) {
	return term.ReadPassword(int(syscall.Stdin))
}
