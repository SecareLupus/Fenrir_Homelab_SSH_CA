package main

import (
	"context"
	"encoding/json"
	"fmt"
	"html/template"
	"log"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"ssh-ca/internal/client"
	"time"
)

var globalConfig *client.Config

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

	// 2. Serve Local Dashboard
	http.HandleFunc("/", handleDashboard)
	http.HandleFunc("/api/status", handleStatus)
	http.HandleFunc("/api/renew", handleRenew)
	http.HandleFunc("/api/launch", handleLaunch)

	port := 4500
	fmt.Printf("SSH-CA Control Center starting on http://localhost:%d\n", port)

	// Auto-open in browser for "GUI" experience
	go func() {
		time.Sleep(1 * time.Second)
		openBrowser(fmt.Sprintf("http://localhost:%d", port))
	}()

	log.Fatal(http.ListenAndServe(fmt.Sprintf(":%d", port), nil))
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
	tmpl, _ := template.ParseFiles("web/client/dashboard.html")
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
