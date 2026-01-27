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
	"crypto/rand"
	"encoding/base64"
	"flag"
	"io"
	"log"
	"net/http"
	"os"
	"os/exec"
	"strings"
	"time"

	"golang.org/x/crypto/ssh"
)

func main() {
	caURL := flag.String("url", "http://ssh-ca.local:8080", "SSH CA Server URL")
	interval := flag.Duration("interval", 5*time.Minute, "Sync interval")
	userCAPath := flag.String("user-ca-path", "/etc/ssh/user_ca.pub", "Path to save User CA public key")
	krlPath := flag.String("krl-path", "/etc/ssh/revoked.krl", "Path to save KRL")
	hostKeyPath := flag.String("host-key-path", "", "Path to host private key (for renewal)")
	hostCertPath := flag.String("host-cert-path", "/etc/ssh/ssh_host_ed25519_key-cert.pub", "Path to host certificate")
	apiKey := flag.String("api-key", os.Getenv("SSH_CA_API_KEY"), "API Key for host renewal")
	flag.Parse()

	log.Printf("Starting SSH CA Agent (Syncing from %s every %s)", *caURL, *interval)

	ticker := time.NewTicker(*interval)
	for ; ; <-ticker.C {
		changed := false

		// 1. Sync User CA Key
		if syncFile(*caURL+"/api/v1/ca/user", *userCAPath, *apiKey) {
			log.Printf("Updated User CA Key at %s", *userCAPath)
			changed = true
		}

		// 2. Sync KRL
		if syncFile(*caURL+"/krl", *krlPath, *apiKey) {
			log.Printf("Updated KRL at %s", *krlPath)
			changed = true
		}

		// 3. Automated Host Renewal
		if *hostKeyPath != "" {
			if checkAndRenew(*caURL, *apiKey, *hostKeyPath, *hostCertPath) {
				log.Printf("Successfully renewed host certificate at %s", *hostCertPath)
				changed = true
			}
		}

		// 4. Reload SSH if needed
		if changed {
			log.Println("Restarting sshd to apply changes...")
			exec.Command("systemctl", "reload", "ssh").Run()
		}
	}
}

func checkAndRenew(caURL, apiKey, hostKeyPath, hostCertPath string) bool {
	// 1. Check if cert exists and is valid
	if data, err := os.ReadFile(hostCertPath); err == nil {
		pubKey, _, _, _, err := ssh.ParseAuthorizedKey(data)
		if err == nil {
			if cert, ok := pubKey.(*ssh.Certificate); ok {
				expiry := time.Unix(int64(cert.ValidBefore), 0)
				remaining := time.Until(expiry)
				// Renew if less than 30 days remaining
				if remaining > 30*24*time.Hour {
					return false
				}
				log.Printf("Certificate expires in %v, initiating renewal...", remaining)
			}
		}
	} else if !os.IsNotExist(err) {
		log.Printf("Error reading host cert: %v", err)
		return false
	} else {
		log.Printf("Host certificate not found at %s, attempting to acquire one...", hostCertPath)
	}

	// 2. Perform Renewal
	pubKeyPath := hostKeyPath + ".pub"
	pubKeyData, err := os.ReadFile(pubKeyPath)
	if err != nil {
		log.Printf("Error reading host public key %s: %v", pubKeyPath, err)
		return false
	}

	// Load private key for PoP (Proof of Possession)
	privKeyData, err := os.ReadFile(hostKeyPath)
	if err != nil {
		log.Printf("Error reading host private key %s: %v", hostKeyPath, err)
		return false
	}
	signer, err := ssh.ParsePrivateKey(privKeyData)
	if err != nil {
		log.Printf("Error parsing host private key: %v", err)
		return false
	}

	retry := true
	var challenge, signature string

	for {
		req, err := http.NewRequest("POST", caURL+"/api/v1/host/renew", strings.NewReader("pubkey="+string(pubKeyData)))
		if err != nil {
			return false
		}
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		if apiKey != "" {
			req.Header.Set("X-Host-API-Key", apiKey)
		}
		if challenge != "" {
			req.Header.Set("X-SSH-Challenge", challenge)
			req.Header.Set("X-SSH-Signature", signature)
		}

		client := &http.Client{Timeout: 10 * time.Second}
		resp, err := client.Do(req)
		if err != nil {
			log.Printf("Renewal request failed: %v", err)
			return false
		}
		defer resp.Body.Close()

		if resp.StatusCode == http.StatusUnauthorized && retry {
			challenge = resp.Header.Get("X-SSH-Challenge")
			if challenge != "" {
				sig, err := signer.Sign(rand.Reader, []byte(challenge))
				if err != nil {
					log.Printf("Failed to sign challenge: %v", err)
					return false
				}
				signature = base64.StdEncoding.EncodeToString(ssh.Marshal(sig))
				retry = false // Only retry once per cycle
				continue
			}
		}

		if resp.StatusCode != http.StatusOK {
			body, _ := io.ReadAll(resp.Body)
			log.Printf("Renewal failed (status %d): %s", resp.StatusCode, string(body))
			return false
		}

		newCert, err := io.ReadAll(resp.Body)
		if err != nil {
			return false
		}

		err = os.WriteFile(hostCertPath, newCert, 0644)
		if err != nil {
			log.Printf("Error saving new host cert: %v", err)
			return false
		}

		return true
	}
}

func syncFile(url, path, apiKey string) bool {
	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return false
	}

	if apiKey != "" {
		req.Header.Set("X-Host-API-Key", apiKey)
	}

	client := &http.Client{Timeout: 10 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		log.Printf("Error fetching %s: %v", url, err)
		return false
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		log.Printf("Failed to sync %s: status %d", url, resp.StatusCode)
		return false
	}

	newData, err := io.ReadAll(resp.Body)
	if err != nil {
		return false
	}

	oldData, _ := os.ReadFile(path)
	if bytes.Equal(newData, oldData) {
		return false
	}

	err = os.WriteFile(path, newData, 0644)
	if err != nil {
		log.Printf("Error writing %s: %v", path, err)
		return false
	}

	return true
}
