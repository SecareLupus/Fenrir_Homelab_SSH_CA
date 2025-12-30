package main

import (
	"bytes"
	"flag"
	"io"
	"log"
	"net/http"
	"os"
	"os/exec"
	"time"
)

func main() {
	caURL := flag.String("url", "http://ssh-ca.local:8080", "SSH CA Server URL")
	interval := flag.Duration("interval", 5*time.Minute, "Sync interval")
	userCAPath := flag.String("user-ca-path", "/etc/ssh/user_ca.pub", "Path to save User CA public key")
	krlPath := flag.String("krl-path", "/etc/ssh/revoked.krl", "Path to save KRL")
	flag.Parse()

	log.Printf("Starting SSH CA Agent (Syncing from %s every %s)", *caURL, *interval)

	ticker := time.NewTicker(*interval)
	for ; ; <-ticker.C {
		changed := false

		// 1. Sync User CA Key
		if syncFile(*caURL+"/api/v1/ca/user", *userCAPath) {
			log.Printf("Updated User CA Key at %s", *userCAPath)
			changed = true
		}

		// 2. Sync KRL
		if syncFile(*caURL+"/krl", *krlPath) {
			log.Printf("Updated KRL at %s", *krlPath)
			changed = true
		}

		// 3. Reload SSH if needed
		if changed {
			log.Println("Restarting sshd to apply changes...")
			exec.Command("systemctl", "reload", "ssh").Run()
		}
	}
}

func syncFile(url, path string) bool {
	resp, err := http.Get(url)
	if err != nil {
		log.Printf("Error fetching %s: %v", url, err)
		return false
	}
	defer resp.Body.Close()

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
