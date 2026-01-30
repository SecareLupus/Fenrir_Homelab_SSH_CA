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
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"os/exec"
	"strings"
	"sync/atomic"
	"time"

	"github.com/coreos/go-systemd/v22/sdjournal"
	"golang.org/x/crypto/ssh"
)

func main() {
	caURL := flag.String("url", "http://ssh-ca.local:8080", "SSH CA Server URL")
	interval := flag.Duration("interval", 1*time.Minute, "Sync interval")
	userCAPath := flag.String("user-ca-path", "/etc/ssh/user_ca.pub", "Path to save User CA public key")
	krlPath := flag.String("krl-path", "/etc/ssh/revoked.krl", "Path to save KRL")
	hostKeyPath := flag.String("host-key-path", "", "Path to host private key (for renewal)")
	hostCertPath := flag.String("host-cert-path", "/etc/ssh/ssh_host_ed25519_key-cert.pub", "Path to host certificate")
	apiKey := flag.String("api-key", os.Getenv("SSH_CA_API_KEY"), "API Key for host renewal")
	syncPAM := flag.Bool("sync-pam", true, "Enable automated synchronization of pam_fenrir.so")
	flag.Parse()

	log.Printf("Starting SSH CA Agent (Syncing from %s every %s)", *caURL, *interval)

	// Start Audit Watcher (Journald)
	go watchJournal(*caURL, *apiKey)

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

		// 4. Sync PAM Module (if enabled)
		if *syncPAM {
			if syncPAMModule(*caURL, *apiKey) {
				log.Printf("Updated PAM module at /lib/security/pam_fenrir.so")
				// We don't necessarily need to reload SSH for a .so update,
				// but it's safe to mark as changed for consistency.
				changed = true
			}
		}

		// 5. Reload SSH if needed
		if changed {
			log.Println("Restarting sshd to apply changes...")
			exec.Command("systemctl", "reload", "ssh").Run()
		}

		// 6. Report Metrics
		reportMetrics(*caURL, *apiKey)
	}
}

type HostMetrics struct {
	Heartbeats uint64  `json:"heartbeats"`
	Load1      float64 `json:"load_1"`
	Load5      float64 `json:"load_5"`
	Load15     float64 `json:"load_15"`
	ActiveSSH  int     `json:"active_ssh"`
}

var heartbeats uint64

func reportMetrics(caURL, apiKey string) {
	atomic.AddUint64(&heartbeats, 1)
	load1, load5, load15 := getSystemLoad()
	activeSSH := countActiveSSHSessions()

	m := HostMetrics{
		Heartbeats: atomic.LoadUint64(&heartbeats),
		Load1:      load1,
		Load5:      load5,
		Load15:     load15,
		ActiveSSH:  activeSSH,
	}

	body, err := json.Marshal(m)
	if err != nil {
		return
	}

	req, err := http.NewRequest("POST", caURL+"/api/v1/host/report", bytes.NewBuffer(body))
	if err != nil {
		return
	}
	req.Header.Set("Content-Type", "application/json")
	if apiKey != "" {
		req.Header.Set("X-Host-API-Key", apiKey)
	}

	client := &http.Client{Timeout: 5 * time.Second}
	resp, err := client.Do(req)
	if err == nil {
		resp.Body.Close()
	}
}

func getSystemLoad() (f1, f5, f15 float64) {
	data, err := os.ReadFile("/proc/loadavg")
	if err != nil {
		return
	}
	fmt.Sscanf(string(data), "%f %f %f", &f1, &f5, &f15)
	return
}

func countActiveSSHSessions() int {
	out, err := exec.Command("pgrep", "-c", "-f", "sshd: [a-zA-Z0-9]").Output()
	if err != nil {
		return 0
	}
	var count int
	fmt.Sscanf(string(out), "%d", &count)
	return count
}

func watchJournal(caURL, apiKey string) {
	j, err := sdjournal.NewJournal()
	if err != nil {
		log.Printf("Error opening journal: %v (Is systemd/journald available?)", err)
		return
	}
	defer j.Close()

	err = j.AddMatch("_COMM=sshd")
	if err != nil {
		log.Printf("Error adding journal match: %v", err)
		return
	}

	err = j.SeekTail()
	if err != nil {
		log.Printf("Error seeking journal tail: %v", err)
		return
	}
	j.Previous() // Skip to end

	for {
		n := j.Wait(2 * time.Second)
		if n == sdjournal.SD_JOURNAL_NOP {
			continue
		}

		for {
			n, err := j.Next()
			if err != nil || n == 0 {
				break
			}

			entry, err := j.GetEntry()
			if err != nil {
				continue
			}

			msg := entry.Fields["MESSAGE"]
			if strings.Contains(msg, "Accepted") || strings.Contains(msg, "session opened") {
				reportAuditEvent(caURL, apiKey, "session_start", msg)
			} else if strings.Contains(msg, "session closed") || strings.Contains(msg, "Disconnected") {
				reportAuditEvent(caURL, apiKey, "session_end", msg)
			}
		}
	}
}

func reportAuditEvent(caURL, apiKey, event, metadata string) {
	payload := struct {
		Event    string `json:"event"`
		Metadata string `json:"metadata"`
	}{
		Event:    event,
		Metadata: metadata,
	}

	body, _ := json.Marshal(payload)
	req, err := http.NewRequest("POST", caURL+"/api/v1/host/audit", bytes.NewBuffer(body))
	if err != nil {
		return
	}
	req.Header.Set("Content-Type", "application/json")
	if apiKey != "" {
		req.Header.Set("X-Host-API-Key", apiKey)
	}

	client := &http.Client{Timeout: 5 * time.Second}
	resp, err := client.Do(req)
	if err == nil {
		resp.Body.Close()
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

func syncPAMModule(caURL, apiKey string) bool {
	// Detect architecture
	arch := "amd64"
	if out, err := exec.Command("uname", "-m").Output(); err == nil {
		m := strings.TrimSpace(string(out))
		if m == "aarch64" || m == "arm64" {
			arch = "arm64"
		}
	}

	url := fmt.Sprintf("%s/api/v1/ca/pam/binary?arch=%s", caURL, arch)
	path := "/lib/security/pam_fenrir.so"

	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return false
	}
	if apiKey != "" {
		req.Header.Set("X-Host-API-Key", apiKey)
	}

	client := &http.Client{Timeout: 30 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		log.Printf("Error fetching PAM binary: %v", err)
		return false
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
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

	// Write to a temporary file first, then rename to ensure atomicity
	tmpPath := path + ".tmp"
	if err := os.WriteFile(tmpPath, newData, 0644); err != nil {
		log.Printf("Error writing temporary PAM binary: %v", err)
		return false
	}

	if err := exec.Command("mv", tmpPath, path).Run(); err != nil {
		log.Printf("Error installing PAM binary: %v", err)
		return false
	}

	return true
}
