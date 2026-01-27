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
	_ "embed"
	"encoding/json"
	"fmt"
	"html/template"
	"log"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"time"

	"github.com/SecareLupus/Fenrir_Homelab_SSH_CA/internal/client"
	"github.com/getlantern/systray"
)

//go:embed assets/icon.png
var iconData []byte

//go:embed assets/dashboard.html
var dashboardHTML string

//go:embed assets/settings.html
var settingsHTML string

var globalConfig *client.Config
var serverPort = 4500
var configPath string

// PersistentConfig stores user settings
type PersistentConfig struct {
	ServerURL string `json:"server_url"`
	APIKey    string `json:"api_key"`
	KeyPath   string `json:"key_path"`
	KeyType   string `json:"key_type"`
}

func main() {
	// Determine config file path
	home, _ := os.UserHomeDir()
	configPath = filepath.Join(home, ".tyr-gui-config.json")

	// Load saved configuration
	loadSavedConfig()

	// If no config exists, we'll show settings on first access
	if globalConfig == nil {
		globalConfig = &client.Config{
			CAURL:      "http://localhost:8080",
			KeyPath:    filepath.Join(home, ".ssh", "id_ed25519"),
			KeyType:    "ed25519",
			AutoEnroll: true,
		}
	}

	// 1. Start Renewal Loop
	go renewalLoop()

	// 2. Start HTTP Server
	go startServer()

	// 3. Start System Tray
	systray.Run(onReady, onExit)
}

func loadSavedConfig() {
	data, err := os.ReadFile(configPath)
	if err != nil {
		return // No saved config
	}

	var pc PersistentConfig
	if err := json.Unmarshal(data, &pc); err != nil {
		log.Printf("Failed to parse config: %v", err)
		return
	}

	home, _ := os.UserHomeDir()
	keyPath := pc.KeyPath
	if keyPath == "" {
		keyPath = filepath.Join(home, ".ssh", "id_ed25519")
	}

	keyType := pc.KeyType
	if keyType == "" {
		keyType = "ed25519"
	}

	globalConfig = &client.Config{
		CAURL:      pc.ServerURL,
		KeyPath:    keyPath,
		KeyType:    keyType,
		APIKey:     pc.APIKey,
		AutoEnroll: true,
	}
}

func saveConfig(pc PersistentConfig) error {
	data, err := json.Marshal(pc)
	if err != nil {
		return err
	}
	return os.WriteFile(configPath, data, 0600)
}

func startServer() {
	http.HandleFunc("/", handleDashboard)
	http.HandleFunc("/settings", handleSettings)
	http.HandleFunc("/api/status", handleStatus)
	http.HandleFunc("/api/renew", handleRenew)
	http.HandleFunc("/api/launch", handleLaunch)
	http.HandleFunc("/api/config", handleConfig)
	http.HandleFunc("/api/config/advanced", handleAdvancedConfig)
	http.HandleFunc("/api/login", handleLogin)

	fmt.Printf("SSH-CA Control Center starting on http://localhost:%d\n", serverPort)
	log.Fatal(http.ListenAndServe(fmt.Sprintf(":%d", serverPort), nil))
}

func onReady() {
	systray.SetIcon(iconData)
	systray.SetTitle("SSH CA")
	systray.SetTooltip("Homelab SSH CA Control Center")

	mStatus := systray.AddMenuItem("Status: Checking...", "Certificate Status")
	mStatus.Disable()

	systray.AddSeparator()

	mDashboard := systray.AddMenuItem("Open Dashboard", "Open the web dashboard")
	mSettings := systray.AddMenuItem("Settings", "Configure Fenrir connection")
	mRenew := systray.AddMenuItem("Renew Certificate", "Manually trigger certificate renewal")

	systray.AddSeparator()

	mQuit := systray.AddMenuItem("Quit", "Quit the application")

	// Update status item in loop
	go func() {
		for {
			id, err := globalConfig.GetIdentity()
			if err == nil {
				if id.HasCert {
					remaining := time.Until(id.CertExpiry).Round(time.Minute)
					mStatus.SetTitle(fmt.Sprintf("Status: Certified (%v)", remaining))
				} else {
					mStatus.SetTitle("Status: Unauthorized")
				}
			} else {
				mStatus.SetTitle("Status: Error")
			}
			time.Sleep(30 * time.Second)
		}
	}()

	for {
		select {
		case <-mDashboard.ClickedCh:
			openBrowser(fmt.Sprintf("http://localhost:%d", serverPort))
		case <-mSettings.ClickedCh:
			openBrowser(fmt.Sprintf("http://localhost:%d/settings", serverPort))
		case <-mRenew.ClickedCh:
			globalConfig.Sign(context.Background(), nil)
		case <-mQuit.ClickedCh:
			systray.Quit()
			return
		}
	}
}

func onExit() {
	os.Exit(0)
}

func renewalLoop() {
	for {
		id, err := globalConfig.GetIdentity()
		if err == nil {
			// If missing or expiring in < 1 hour
			if !id.HasCert || time.Until(id.CertExpiry) < 1*time.Hour {
				log.Println("Background renewal triggered...")
				globalConfig.Sign(context.Background(), nil)
			}
		}
		time.Sleep(15 * time.Minute)
	}
}

func handleDashboard(w http.ResponseWriter, r *http.Request) {
	// Check if configured
	if globalConfig.APIKey == "" {
		http.Redirect(w, r, "/settings", http.StatusSeeOther)
		return
	}

	tmpl, err := template.New("dashboard").Parse(dashboardHTML)
	if err != nil {
		http.Error(w, err.Error(), 500)
		return
	}
	tmpl.Execute(w, nil)
}

func handleSettings(w http.ResponseWriter, r *http.Request) {
	tmpl, err := template.New("settings").Parse(settingsHTML)
	if err != nil {
		http.Error(w, err.Error(), 500)
		return
	}
	tmpl.Execute(w, nil)
}

func handleStatus(w http.ResponseWriter, r *http.Request) {
	id, _ := globalConfig.GetIdentity()
	expiryText := "No certificate"
	if id.HasCert {
		expiryText = fmt.Sprintf("%v", time.Until(id.CertExpiry).Round(time.Minute))
	}

	json.NewEncoder(w).Encode(map[string]any{
		"HasCert":     id.HasCert,
		"Fingerprint": id.Fingerprint,
		"ExpiryText":  expiryText,
	})
}

func handleRenew(w http.ResponseWriter, r *http.Request) {
	err := globalConfig.Sign(context.Background(), nil)
	if err != nil {
		http.Error(w, err.Error(), 500)
		return
	}
	w.Write([]byte("OK"))
}

func handleLaunch(w http.ResponseWriter, r *http.Request) {
	host := r.URL.Query().Get("host")
	if host == "" {
		return
	}

	var cmd *exec.Cmd
	switch runtime.GOOS {
	case "windows":
		cmd = exec.Command("cmd", "/c", "start", "ssh", host)
	case "darwin":
		cmd = exec.Command("osascript", "-e", fmt.Sprintf(`tell app "Terminal" to do script "ssh %s"`, host))
	default: // Linux
		cmd = exec.Command("x-terminal-emulator", "-e", "ssh", host)
	}

	err := cmd.Start()
	if err != nil {
		http.Error(w, err.Error(), 500)
		return
	}
	w.Write([]byte("Launched"))
}

func handleConfig(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case "GET":
		data, _ := os.ReadFile(configPath)
		var pc PersistentConfig
		json.Unmarshal(data, &pc)

		// Don't send the actual API key, just indicate if it exists
		response := map[string]any{
			"server_url":  pc.ServerURL,
			"key_path":    pc.KeyPath,
			"key_type":    pc.KeyType,
			"has_api_key": pc.APIKey != "",
		}
		json.NewEncoder(w).Encode(response)

	case "POST":
		var req struct {
			ServerURL string `json:"server_url"`
			APIKey    string `json:"api_key"`
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			http.Error(w, err.Error(), 400)
			return
		}

		// Load existing config to preserve other settings
		data, _ := os.ReadFile(configPath)
		var pc PersistentConfig
		json.Unmarshal(data, &pc)

		// Update with new values
		pc.ServerURL = req.ServerURL
		pc.APIKey = strings.TrimSpace(req.APIKey)

		if err := saveConfig(pc); err != nil {
			http.Error(w, "Failed to save config", 500)
			return
		}

		// Update global config
		globalConfig.CAURL = pc.ServerURL
		globalConfig.APIKey = pc.APIKey

		w.Write([]byte("OK"))

	case "DELETE":
		os.Remove(configPath)
		w.Write([]byte("OK"))
	}
}

func handleAdvancedConfig(w http.ResponseWriter, r *http.Request) {
	if r.Method != "POST" {
		http.Error(w, "Method not allowed", 405)
		return
	}

	var req struct {
		KeyPath string `json:"key_path"`
		KeyType string `json:"key_type"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, err.Error(), 400)
		return
	}

	// Load existing config
	data, _ := os.ReadFile(configPath)
	var pc PersistentConfig
	json.Unmarshal(data, &pc)

	// Update advanced settings
	if req.KeyPath != "" {
		pc.KeyPath = req.KeyPath
		globalConfig.KeyPath = req.KeyPath
	}
	if req.KeyType != "" {
		pc.KeyType = req.KeyType
		globalConfig.KeyType = req.KeyType
	}

	if err := saveConfig(pc); err != nil {
		http.Error(w, "Failed to save config", 500)
		return
	}

	w.Write([]byte("OK"))
}

func handleLogin(w http.ResponseWriter, r *http.Request) {
	if r.Method != "POST" {
		http.Error(w, "Method not allowed", 405)
		return
	}

	var req struct {
		ServerURL string `json:"server_url"`
		Username  string `json:"username"`
		Password  string `json:"password"`
		MFACode   string `json:"mfa_code"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, err.Error(), 400)
		return
	}

	// Call Fenrir's login API
	loginReq := map[string]string{
		"username": req.Username,
		"password": req.Password,
	}
	if req.MFACode != "" {
		loginReq["totp_code"] = req.MFACode
	}

	body, _ := json.Marshal(loginReq)
	resp, err := http.Post(req.ServerURL+"/api/auth/login", "application/json", bytes.NewReader(body))
	if err != nil {
		json.NewEncoder(w).Encode(map[string]string{"error": "Connection failed"})
		return
	}
	defer resp.Body.Close()

	var loginResp struct {
		APIKey      string `json:"api_key"`
		MFARequired bool   `json:"mfa_required"`
		Error       string `json:"error"`
	}
	json.NewDecoder(resp.Body).Decode(&loginResp)

	if loginResp.MFARequired {
		json.NewEncoder(w).Encode(map[string]bool{"mfa_required": true})
		return
	}

	if loginResp.Error != "" || resp.StatusCode != 200 {
		w.WriteHeader(resp.StatusCode)
		json.NewEncoder(w).Encode(map[string]string{"error": loginResp.Error})
		return
	}

	// Save the API key
	data, _ := os.ReadFile(configPath)
	var pc PersistentConfig
	json.Unmarshal(data, &pc)

	pc.ServerURL = req.ServerURL
	pc.APIKey = loginResp.APIKey

	if err := saveConfig(pc); err != nil {
		http.Error(w, "Failed to save config", 500)
		return
	}

	// Update global config
	globalConfig.CAURL = pc.ServerURL
	globalConfig.APIKey = pc.APIKey

	json.NewEncoder(w).Encode(map[string]string{"status": "success"})
}

func openBrowser(url string) {
	var err error
	switch runtime.GOOS {
	case "linux":
		err = exec.Command("xdg-open", url).Start()
	case "windows":
		err = exec.Command("rundll32", "url.dll,FileProtocolHandler", url).Start()
	case "darwin":
		err = exec.Command("open", url).Start()
	}
	if err != nil {
		log.Printf("Failed to open browser: %v", err)
	}
}
