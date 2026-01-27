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
	 "github.com/SecareLupus/Fenrir_Homelab_SSH_CA/internal/client"
	"time"

	"github.com/getlantern/systray"
)

//go:embed assets/icon.png
var iconData []byte

//go:embed assets/dashboard.html
var dashboardHTML string

var globalConfig *client.Config
var serverPort = 4500

func main() {
	home, _ := os.UserHomeDir()
	globalConfig = &client.Config{
		CAURL:      "http://localhost:8080",
		KeyPath:    filepath.Join(home, ".ssh", "id_ed25519"),
		KeyType:    "ed25519",
		AutoEnroll: true,
	}

	// 1. Start Renewal Loop
	go renewalLoop()

	// 2. Start HTTP Server
	go startServer()

	// 3. Start System Tray
	systray.Run(onReady, onExit)
}

func startServer() {
	http.HandleFunc("/", handleDashboard)
	http.HandleFunc("/api/status", handleStatus)
	http.HandleFunc("/api/renew", handleRenew)
	http.HandleFunc("/api/launch", handleLaunch)

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
	mRenew := systray.AddMenuItem("Renew Certificate", "Manually trigger certificate renewal")

	systray.AddSeparator()

	mQuit := systray.AddMenuItem("Quit", "Quit the application")

	// Update status item in loop
	go func() {
		for {
			id, err := globalConfig.GetIdentity()
			if err == nil {
				if id.HasCert {
					mStatus.SetTitle(fmt.Sprintf("Status: Certified (%v)", time.Until(id.CertExpiry).Round(time.Minute)))
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
	tmpl, err := template.New("dashboard").Parse(dashboardHTML)
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
