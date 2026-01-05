package web

import (
	"fmt"
	"html/template"
	"log"
	"net/http"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"ssh-ca/internal/auth"
	"ssh-ca/internal/ca"
	"ssh-ca/internal/config"
	"ssh-ca/internal/db"

	"crypto/rand"
	"encoding/base64"
	"encoding/hex"

	"github.com/xlzd/gotp"
	"golang.org/x/crypto/ssh"
)

type Server struct {
	cfg  *config.Config
	db   *db.DB
	ca   *ca.Service
	mux  *http.ServeMux
	tmpl *template.Template
	// challenges stores active PoP challenges: fingerprint -> {challenge, expiry}
	challenges map[string]challenge
}

type challenge struct {
	val     string
	expires time.Time
}

func NewServer(cfg *config.Config, db *db.DB, ca *ca.Service) *Server {
	s := &Server{
		cfg:        cfg,
		db:         db,
		ca:         ca,
		mux:        http.NewServeMux(),
		challenges: make(map[string]challenge),
	}
	s.loadTemplates()
	s.routes()
	return s
}

func (s *Server) loadTemplates() {
	pattern := filepath.Join("web", "templates", "*.html")
	tmpl, err := template.ParseGlob(pattern)
	if err != nil {
		log.Fatalf("failed to parse templates: %v", err)
	}
	s.tmpl = tmpl
}

func (s *Server) render(w http.ResponseWriter, name string, data any) {
	// Re-parse in dev mode for hot reload (optional, skipped for simplicity)
	if err := s.tmpl.ExecuteTemplate(w, "layout.html", data); err != nil {
		log.Printf("render error: %v", err)
		http.Error(w, "Internal Server Error", 500)
	}
}

func (s *Server) routes() {
	fs := http.FileServer(http.Dir("web/static"))
	s.mux.Handle("/static/", http.StripPrefix("/static/", fs))

	s.mux.HandleFunc("/", s.handleIndex)
	s.mux.HandleFunc("/login", s.handleLogin)
	s.mux.HandleFunc("/login/mfa", s.handleLoginMFA)
	s.mux.HandleFunc("/logout", s.handleLogout)
	s.mux.HandleFunc("/mfa/setup", s.handleMFASetup)
	s.mux.HandleFunc("/cert/request", s.handleCertRequest)
	s.mux.HandleFunc("/api/keys/generate", s.handleAPIKeyGenerate)
	s.mux.HandleFunc("/admin/users", s.handleAdminUsers)
	s.mux.HandleFunc("/admin/users/toggle", s.handleAdminUserToggle)
	s.mux.HandleFunc("/admin/audit", s.handleAdminAudit)
	s.mux.HandleFunc("/admin/audit/identity", s.handleAdminAuditIdentity)
	s.mux.HandleFunc("/admin/hosts/sign", s.handleAdminHostSign)
	s.mux.HandleFunc("/admin/hosts/apikey", s.handleAdminHostAPIKey)
	s.mux.HandleFunc("/admin/revoke", s.handleAdminRevoke)
	s.mux.HandleFunc("/admin/offline", s.handleAdminOffline)
	s.mux.HandleFunc("/admin/offline/sign", s.handleAdminOfflineSign)
	s.mux.HandleFunc("/krl", s.handleKRL)
	s.mux.HandleFunc("/api/v1/ca/user", s.handleAPIUserCA)
	s.mux.HandleFunc("/api/v1/ca/host", s.handleAPIHostCA)
	s.mux.HandleFunc("/api/v1/host/renew", s.handleAPIHostRenew)
	s.mux.HandleFunc("/api/v1/health", s.handleHealth)
}

func (s *Server) Start() error {
	return http.ListenAndServe(s.cfg.BindAddr, s.mux)
}

func (s *Server) handleLogin(w http.ResponseWriter, r *http.Request) {
	if r.Method == "GET" {
		s.renderPage(w, "login.html", nil)
		return
	}

	username := r.FormValue("username")
	password := r.FormValue("password")

	// 1. Check if ANY user exists. If not, bootstrap admin.
	// This is a simple "first run" check.
	// Optimization: This check should be cached or done at startup, but fine here for MVP.
	_, err := s.db.GetUserHash("admin") // Assuming admin is the bootstrap target
	if err != nil {
		// If admin doesn't exist, and we're trying to log in as admin...
		// OR: strictly check count.
		// Simpler: If username is "admin" and DB has no users...
		// Let's rely on standard bootstrap if "admin" retrieval fails.

		// ACTUALLY: Let's create admin if it doesn't exist AND this is the first login attempt.
		// Use a specific "First Run" logic or just bootstrap silently if user is admin.
		if username == "admin" {
			// Check if we can create it
			hash, _ := auth.HashPassword(password)
			if err := s.db.CreateUser("admin", hash); err == nil {
				// Created successfully, proceed to login
				log.Printf("Bootstrapped admin user")
			}
		}
	}

	// 2. Authenticate Password
	hash, err := s.db.GetUserHash(username)
	if err != nil || !auth.CheckPassword(password, hash) {
		s.renderPage(w, "login.html", map[string]any{"Error": "Invalid credentials"})
		return
	}

	// 3. Check MFA
	mfaSecret, _ := s.db.GetUserMFASecret(username)
	if mfaSecret != "" {
		// Store username in a cookie but marked as "pre-mfa"
		http.SetCookie(w, &http.Cookie{
			Name:     "mfa_pending_user",
			Value:    username,
			Path:     "/",
			HttpOnly: true,
			Expires:  time.Now().Add(5 * time.Minute),
		})
		http.Redirect(w, r, "/login/mfa", http.StatusSeeOther)
		return
	}

	// 4. Success - Set Session Cookie
	s.setSession(w, username)
	http.Redirect(w, r, "/", http.StatusSeeOther)
}

func (s *Server) setSession(w http.ResponseWriter, username string) {
	http.SetCookie(w, &http.Cookie{
		Name:     "session_user",
		Value:    username,
		Path:     "/",
		HttpOnly: true,
		Expires:  time.Now().Add(24 * time.Hour),
	})
}

func (s *Server) handleLogout(w http.ResponseWriter, r *http.Request) {
	http.SetCookie(w, &http.Cookie{
		Name:     "session_user",
		Value:    "",
		Path:     "/",
		HttpOnly: true,
		MaxAge:   -1,
	})
	http.Redirect(w, r, "/login", http.StatusSeeOther)
}

func (s *Server) authenticate(r *http.Request) string {
	// 1. Check for API Key in header
	apiKey := r.Header.Get("X-API-Key")
	if apiKey != "" {
		hash := auth.HashAPIKey(apiKey)
		username, err := s.db.GetUserByAPIKey(hash)
		if err == nil {
			return username
		}
	}

	// 2. Check for Session Cookie
	cookie, err := r.Cookie("session_user")
	if err == nil && cookie.Value != "" {
		return cookie.Value
	}

	return ""
}

func (s *Server) handleIndex(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != "/" {
		http.NotFound(w, r)
		return
	}

	username := s.authenticate(r)
	if username == "" {
		http.Redirect(w, r, "/login", http.StatusSeeOther)
		return
	}

	userCA := ssh.MarshalAuthorizedKey(s.ca.GetUserCAPublicKey())
	hostCA := ssh.MarshalAuthorizedKey(s.ca.GetHostCAPublicKey())

	data := map[string]any{
		"User":      username,
		"IsAdmin":   username == "admin", // MVP: hardcoded admin
		"UserCAKey": string(userCA),
		"HostCAKey": string(hostCA),
		"Mode":      s.cfg.Mode,
	}
	s.renderPage(w, "dashboard.html", data)
}

func (s *Server) handleAdminOffline(w http.ResponseWriter, r *http.Request) {
	username := s.authenticate(r)
	if username != "admin" {
		http.Error(w, "Forbidden", 403)
		return
	}

	userCA := ssh.MarshalAuthorizedKey(s.ca.GetUserCAPublicKey())
	hostCA := ssh.MarshalAuthorizedKey(s.ca.GetHostCAPublicKey())

	data := map[string]any{
		"User":      username,
		"IsAdmin":   true,
		"UserCAKey": string(userCA),
		"HostCAKey": string(hostCA),
	}
	s.renderPage(w, "admin_offline.html", data)
}

func (s *Server) handleAdminOfflineSign(w http.ResponseWriter, r *http.Request) {
	if r.Method != "POST" {
		http.Redirect(w, r, "/admin/offline", http.StatusSeeOther)
		return
	}

	username := s.authenticate(r)
	if username != "admin" {
		http.Error(w, "Forbidden", 403)
		return
	}

	pubKeyStr := r.FormValue("pubkey")
	certType := r.FormValue("type") // "user" or "host"
	ttlStr := r.FormValue("ttl")
	ttl, _ := strconv.ParseUint(ttlStr, 10, 64)

	pubKey, _, _, _, err := ssh.ParseAuthorizedKey([]byte(pubKeyStr))
	if err != nil {
		http.Error(w, "Invalid public key", 400)
		return
	}

	var cert *ssh.Certificate
	if certType == "user" {
		cert, err = s.ca.SignIntermediateUserCertificate(pubKey, "intermediate-user-ca", ttl)
	} else {
		cert, err = s.ca.SignIntermediateHostCertificate(pubKey, "intermediate-host-ca", ttl)
	}

	if err != nil {
		http.Error(w, "Signing failed: "+err.Error(), 500)
		return
	}

	// Log it
	uid, _ := s.db.GetUserID(username)
	s.db.LogEvent(&uid, "intermediate_cert_signed", certType)

	w.Header().Set("Content-Type", "application/octet-stream")
	w.Write(ssh.MarshalAuthorizedKey(cert))
}


func (s *Server) handleCertRequest(w http.ResponseWriter, r *http.Request) {
	if r.Method != "POST" {
		http.Redirect(w, r, "/", http.StatusSeeOther)
		return
	}

	// 1. Parse Input
	pubKeyStr := r.FormValue("pubkey")
	ttlStr := r.FormValue("ttl")
	pubKey, _, _, _, err := ssh.ParseAuthorizedKey([]byte(pubKeyStr))
	if err != nil {
		http.Error(w, "Invalid public key", 400)
		return
	}
	fingerprint := ssh.FingerprintSHA256(pubKey)

	var username string
	isNewKey := false

	// 2. Authentication Decision
	apiKey := r.Header.Get("X-API-Key")
	if apiKey != "" {
		// Enrollment path
		hash := auth.HashAPIKey(apiKey)
		var err error
		username, err = s.db.GetUserByAPIKey(hash)
		if err != nil {
			http.Error(w, "Invalid API Key", 401)
			return
		}
		isNewKey = true
	} else {
		// Renewal path via PoP
		owner, err := s.db.CheckPublicKeyOwnership(fingerprint)
		if err != nil {
			http.Error(w, "Key not enrolled. API Key required for initial setup.", 401)
			return
		}
		if !s.db.IsUserEnabled(owner) {
			http.Error(w, "User account disabled", 403)
			return
		}
		username = owner

		ok, _ := s.verifyPoP(w, r, pubKey)
		if !ok {
			return
		}

		uid, _ := s.db.GetUserID(username)
		s.db.LogEvent(&uid, "cert_renew_pop", fingerprint)
	}

	// 3. Register Key if new
	if isNewKey {
		uid, _ := s.db.GetUserID(username)
		s.db.RegisterPublicKey(uid, fingerprint, pubKey.Type(), pubKeyStr, "Enrolled via CLI")
		s.db.LogEvent(&uid, "key_enrolled", fingerprint)
	}

	// 4. Sign Certificate
	ttl, _ := strconv.ParseUint(ttlStr, 10, 64)
	if ttl == 0 {
		ttl = 3600
	}
	if ttl > 86400 {
		ttl = 86400
	}

	principals := []string{username}
	cert, err := s.ca.SignUserCertificate(pubKey, username, principals, ttl)
	if err != nil {
		http.Error(w, "Signing failed", 500)
		return
	}

	// Store in DB
	s.db.StoreCertificate(cert.Serial, fingerprint, "user", strings.Join(principals, ","), int64(cert.ValidAfter), int64(cert.ValidBefore))

	w.Header().Set("Content-Type", "text/plain")
	w.Write(ssh.MarshalAuthorizedKey(cert))
}

func (s *Server) handleAPIKeyGenerate(w http.ResponseWriter, r *http.Request) {
	if r.Method != "POST" {
		http.Redirect(w, r, "/", http.StatusSeeOther)
		return
	}

	username := s.authenticate(r)
	if username == "" {
		http.Error(w, "Unauthorized", 401)
		return
	}

	userId, err := s.db.GetUserID(username)
	if err != nil {
		http.Error(w, "User not found", 404)
		return
	}

	// Generate a 32-byte hex key
	rawKey := make([]byte, 32)
	if _, err := rand.Read(rawKey); err != nil {
		http.Error(w, "Key generation failed", 500)
		return
	}
	apiKey := hex.EncodeToString(rawKey)
	hash := auth.HashAPIKey(apiKey)

	if err := s.db.CreateAPIKey(userId, hash, "Default Key"); err != nil {
		log.Printf("Error storing API key: %v", err)
		http.Error(w, "Failed to store key", 500)
		return
	}

	// For MVP, we'll just show the key once in a simple page or redirected param.
	// Properly, this should be a flash message or a specific "key created" view.
	s.renderPage(w, "dashboard.html", map[string]any{
		"User":      username,
		"IsAdmin":   username == "admin",
		"NewAPIKey": apiKey,
		"UserCAKey": string(ssh.MarshalAuthorizedKey(s.ca.GetUserCAPublicKey())),
		"HostCAKey": string(ssh.MarshalAuthorizedKey(s.ca.GetHostCAPublicKey())),
	})
}

// renderPage helps avoid block collisions by parsing layout + page on fly (dev friendly)
// or cloning/re-associating (prod friendly).
// For this scale, parsing on fly is fine and easiest for avoiding "content" collisions.
func (s *Server) renderPage(w http.ResponseWriter, page string, data any) {
	tmpl, err := template.ParseFiles(
		filepath.Join("web", "templates", "layout.html"),
		filepath.Join("web", "templates", page),
	)
	if err != nil {
		http.Error(w, err.Error(), 500)
		return
	}
	tmpl.Execute(w, data)
}

func (s *Server) handleAdminUsers(w http.ResponseWriter, r *http.Request) {
	username := s.authenticate(r)
	if username != "admin" { // MVP: only 'admin' is admin
		http.Error(w, "Forbidden", 403)
		return
	}

	users, err := s.db.ListUsers()
	if err != nil {
		http.Error(w, err.Error(), 500)
		return
	}

	s.renderPage(w, "admin_users.html", map[string]any{
		"User":  username,
		"Users": users,
	})
}

func (s *Server) handleAdminUserToggle(w http.ResponseWriter, r *http.Request) {
	if r.Method != "POST" {
		http.Redirect(w, r, "/admin/users", http.StatusSeeOther)
		return
	}

	admin := s.authenticate(r)
	if admin != "admin" {
		http.Error(w, "Forbidden", 403)
		return
	}

	target := r.FormValue("username")
	action := r.FormValue("action") // "enable" or "disable"

	if target == "admin" {
		http.Error(w, "Cannot disable admin", 400)
		return
	}

	enabled := action == "enable"
	if err := s.db.SetUserEnabled(target, enabled); err != nil {
		http.Error(w, err.Error(), 500)
		return
	}

	http.Redirect(w, r, "/admin/users", http.StatusSeeOther)
}

func (s *Server) handleAdminAudit(w http.ResponseWriter, r *http.Request) {
	username := s.authenticate(r)
	if username != "admin" {
		http.Error(w, "Forbidden", 403)
		return
	}

	logs, err := s.db.ListAuditLogs(100) // Last 100 events
	if err != nil {
		http.Error(w, err.Error(), 500)
		return
	}

	s.renderPage(w, "admin_audit.html", map[string]any{
		"User": username,
		"Logs": logs,
	})
}

func (s *Server) handleAdminAuditIdentity(w http.ResponseWriter, r *http.Request) {
	username := s.authenticate(r)
	if username != "admin" {
		http.Error(w, "Forbidden", 403)
		return
	}

	since := r.URL.Query().Get("since")
	data := map[string]any{
		"User":  username,
		"Since": since,
	}

	if since != "" {
		users, _ := s.db.ListUsersCreatedSince(since)
		keys, _ := s.db.ListKeysCreatedSince(since)
		data["AuditResults"] = map[string]any{
			"Users": users,
			"Keys":  keys,
		}
	}

	s.renderPage(w, "admin_audit_identity.html", data)
}

func (s *Server) handleAdminHostSign(w http.ResponseWriter, r *http.Request) {
	username := s.authenticate(r)
	if username != "admin" {
		http.Error(w, "Forbidden", 403)
		return
	}

	if r.Method == "GET" {
		hosts, _ := s.db.ListHosts()
		s.renderPage(w, "admin_host_sign.html", map[string]any{
			"User":  username,
			"Hosts": hosts,
		})
		return
	}

	// POST: Sign Host Key
	pubKeyStr := r.FormValue("pubkey")
	hostname := r.FormValue("hostname")
	ttlStr := r.FormValue("ttl")

	pubKey, _, _, _, err := ssh.ParseAuthorizedKey([]byte(pubKeyStr))
	if err != nil {
		http.Error(w, "Invalid public key", 400)
		return
	}

	// Register host if not exists
	fingerprint := ssh.FingerprintSHA256(pubKey)
	_ = s.db.RegisterHost(hostname, fingerprint)

	ttl, _ := strconv.ParseUint(ttlStr, 10, 64)
	if ttl == 0 {
		ttl = 31536000
	} // Default 1 year for hosts

	principals := []string{hostname}
	cert, err := s.ca.SignHostCertificate(pubKey, hostname, principals, ttl)
	if err != nil {
		http.Error(w, "Signing failed", 500)
		return
	}

	// Log it
	uid, _ := s.db.GetUserID(username)
	s.db.LogEvent(&uid, "host_cert_signed", hostname)

	w.Header().Set("Content-Disposition", fmt.Sprintf("attachment; filename=\"%s-cert.pub\"", hostname))
	w.Header().Set("Content-Type", "text/plain")
	w.Write(ssh.MarshalAuthorizedKey(cert))
}

func (s *Server) handleAdminHostAPIKey(w http.ResponseWriter, r *http.Request) {
	username := s.authenticate(r)
	if username != "admin" {
		http.Error(w, "Forbidden", 403)
		return
	}

	if r.Method != "POST" {
		http.Error(w, "Method not allowed", 405)
		return
	}

	hostname := r.FormValue("hostname")
	if hostname == "" {
		http.Error(w, "Missing hostname", 400)
		return
	}

	// Generate a random API key
	key := make([]byte, 32)
	rand.Read(key)
	apiKey := base64.StdEncoding.EncodeToString(key)

	hash := auth.HashAPIKey(apiKey)
	if err := s.db.SetHostAPIKey(hostname, hash); err != nil {
		http.Error(w, "Failed to save API key", 500)
		return
	}

	uid, _ := s.db.GetUserID(username)
	s.db.LogEvent(&uid, "host_api_key_generated", hostname)

	s.renderPage(w, "admin_host_apikey.html", map[string]any{
		"User":     username,
		"Hostname": hostname,
		"APIKey":   apiKey,
	})
}

func (s *Server) handleAdminRevoke(w http.ResponseWriter, r *http.Request) {
	if r.Method != "POST" {
		http.Redirect(w, r, "/admin/audit", http.StatusSeeOther)
		return
	}

	username := s.authenticate(r)
	if username != "admin" {
		http.Error(w, "Forbidden", 403)
		return
	}

	fingerprint := r.FormValue("fingerprint")
	reason := r.FormValue("reason")
	if reason == "" {
		reason = "Administrative revocation"
	}

	if err := s.db.RevokeKeyByFingerprint(fingerprint, reason); err != nil {
		http.Error(w, err.Error(), 500)
		return
	}

	uid, _ := s.db.GetUserID(username)
	s.db.LogEvent(&uid, "key_revoked", fingerprint)

	http.Redirect(w, r, "/admin/audit", http.StatusSeeOther)
}

func (s *Server) handleKRL(w http.ResponseWriter, r *http.Request) {
	if !s.checkHardenedAuth(w, r) {
		return
	}
	keys, err := s.db.ListRevokedPublicKeys()
	if err != nil {
		http.Error(w, err.Error(), 500)
		return
	}

	w.Header().Set("Content-Type", "text/plain")
	for _, k := range keys {
		w.Write([]byte(k + "\n"))
	}
}

func (s *Server) handleLoginMFA(w http.ResponseWriter, r *http.Request) {
	cookie, err := r.Cookie("mfa_pending_user")
	if err != nil || cookie.Value == "" {
		http.Redirect(w, r, "/login", http.StatusSeeOther)
		return
	}
	username := cookie.Value

	if r.Method == "GET" {
		s.renderPage(w, "login_mfa.html", map[string]any{"User": username})
		return
	}

	code := r.FormValue("code")
	secret, _ := s.db.GetUserMFASecret(username)

	// Check TOTP first
	totp := gotp.NewDefaultTOTP(secret)
	valid := totp.Verify(code, time.Now().Unix())

	// If TOTP fails, check backup codes
	if !valid {
		hash := auth.HashAPIKey(code) // Using same hash as API keys
		valid, _ = s.db.VerifyBackupCode(username, hash)
	}

	if valid {
		// Clear pending cookie
		http.SetCookie(w, &http.Cookie{Name: "mfa_pending_user", MaxAge: -1, Path: "/"})
		s.setSession(w, username)
		http.Redirect(w, r, "/", http.StatusSeeOther)
	} else {
		s.renderPage(w, "login_mfa.html", map[string]any{"User": username, "Error": "Invalid MFA code or backup code"})
	}
}

func (s *Server) handleMFASetup(w http.ResponseWriter, r *http.Request) {
	username := s.authenticate(r)
	if username == "" {
		http.Redirect(w, r, "/login", http.StatusSeeOther)
		return
	}

	if r.Method == "GET" {
		// Check if already enabled
		current, _ := s.db.GetUserMFASecret(username)
		if current != "" {
			s.renderPage(w, "dashboard.html", map[string]any{
				"User": username, "Error": "MFA is already enabled.",
				"UserCAKey": string(ssh.MarshalAuthorizedKey(s.ca.GetUserCAPublicKey())),
				"HostCAKey": string(ssh.MarshalAuthorizedKey(s.ca.GetHostCAPublicKey())),
			})
			return
		}

		secret := gotp.RandomSecret(16)
		// We'll show the secret and a provisioning URI (for QR)
		totp := gotp.NewDefaultTOTP(secret)
		uri := totp.ProvisioningUri(username, "SSH-CA")

		s.renderPage(w, "mfa_setup.html", map[string]any{
			"User":   username,
			"Secret": secret,
			"URI":    uri,
		})
		return
	}

	// POST: Verify and Enable
	secret := r.FormValue("secret")
	code := r.FormValue("code")

	totp := gotp.NewDefaultTOTP(secret)
	if totp.Verify(code, time.Now().Unix()) {
		s.db.SetUserMFASecret(username, secret)
		uid, _ := s.db.GetUserID(username)
		s.db.LogEvent(&uid, "mfa_enabled", "")

		// Generate backup codes
		codes, err := s.generateBackupCodes(username)
		if err != nil {
			log.Printf("failed to generate backup codes: %v", err)
		}

		s.renderPage(w, "mfa_backup_codes.html", map[string]any{
			"User":  username,
			"Codes": codes,
		})
	} else {
		// Redirect back with error (simulated here)
		http.Error(w, "Invalid verification code", 400)
	}
}

func (s *Server) generateBackupCodes(username string) ([]string, error) {
	var plainCodes []string
	var hashedCodes []string
	for i := 0; i < 10; i++ {
		code := make([]byte, 8)
		if _, err := rand.Read(code); err != nil {
			return nil, err
		}
		plain := hex.EncodeToString(code)
		plainCodes = append(plainCodes, plain)
		hashedCodes = append(hashedCodes, auth.HashAPIKey(plain))
	}
	err := s.db.SetBackupCodes(username, hashedCodes)
	return plainCodes, err
}

func (s *Server) handleAPIUserCA(w http.ResponseWriter, r *http.Request) {
	if !s.checkHardenedAuth(w, r) {
		return
	}
	w.Header().Set("Content-Type", "text/plain")
	w.Write(ssh.MarshalAuthorizedKey(s.ca.GetUserCAPublicKey()))
}

func (s *Server) handleAPIHostCA(w http.ResponseWriter, r *http.Request) {
	if !s.checkHardenedAuth(w, r) {
		return
	}
	w.Header().Set("Content-Type", "text/plain")
	w.Write(ssh.MarshalAuthorizedKey(s.ca.GetHostCAPublicKey()))
}

func (s *Server) handleHealth(w http.ResponseWriter, r *http.Request) {
	w.Write([]byte("OK"))
}

func (s *Server) handleAPIHostRenew(w http.ResponseWriter, r *http.Request) {
	if r.Method != "POST" {
		http.Error(w, "Method not allowed", 405)
		return
	}

	pubkeyStr := r.FormValue("pubkey")
	if pubkeyStr == "" {
		http.Error(w, "Missing pubkey", 400)
		return
	}

	pubKey, _, _, _, err := ssh.ParseAuthorizedKey([]byte(pubkeyStr))
	if err != nil {
		http.Error(w, "Invalid public key", 400)
		return
	}
	fingerprint := ssh.FingerprintSHA256(pubKey)

	apiKey := r.Header.Get("X-Host-API-Key")
	var hostname string

	if apiKey != "" {
		hash := auth.HashAPIKey(apiKey)
		hostname, err = s.db.GetHostByAPIKey(hash)
		if err != nil {
			http.Error(w, "Unauthorized (Invalid API Key)", 401)
			return
		}
	} else {
		// Attempt PoP renewal
		var err error
		hostname, err = s.db.CheckHostPublicKeyOwnership(fingerprint)
		if err != nil {
			http.Error(w, "Host key not enrolled. API Key required for initial setup.", 401)
			return
		}

		ok, _ := s.verifyPoP(w, r, pubKey)
		if !ok {
			return
		}
	}

	// Sign the host key
	principals := []string{hostname}
	cert, err := s.ca.SignHostCertificate(pubKey, hostname, principals, 365*24*3600)
	if err != nil {
		log.Printf("host renewal failed for %s: %v", hostname, err)
		http.Error(w, "Internal server error during signing", 500)
		return
	}

	w.Header().Set("Content-Type", "text/plain")
	w.Write(ssh.MarshalAuthorizedKey(cert))
}

func (s *Server) verifyPoP(w http.ResponseWriter, r *http.Request, pubKey ssh.PublicKey) (bool, string) {
	fingerprint := ssh.FingerprintSHA256(pubKey)
	sigBase64 := r.Header.Get("X-SSH-Signature")
	challengeVal := r.Header.Get("X-SSH-Challenge")

	if sigBase64 == "" {
		// Generate Challenge
		cBytes := make([]byte, 32)
		rand.Read(cBytes)
		cStr := base64.StdEncoding.EncodeToString(cBytes)
		s.challenges[fingerprint] = challenge{val: cStr, expires: time.Now().Add(5 * time.Minute)}

		w.Header().Set("X-SSH-Challenge", cStr)
		http.Error(w, "Proof of Possession required", 401)
		return false, "PoP required"
	}

	// Verify Challenge
	stored, ok := s.challenges[fingerprint]
	if !ok || stored.val != challengeVal || time.Now().After(stored.expires) {
		http.Error(w, "Invalid or expired challenge", 401)
		return false, "Invalid challenge"
	}
	delete(s.challenges, fingerprint)

	sigBytes, err := base64.StdEncoding.DecodeString(sigBase64)
	if err != nil {
		http.Error(w, "Invalid signature format", 400)
		return false, "Invalid signature"
	}
	var sig ssh.Signature
	if err := ssh.Unmarshal(sigBytes, &sig); err != nil {
		http.Error(w, "Invalid signature encoding", 400)
		return false, "Invalid signature encoding"
	}

	if err := pubKey.Verify([]byte(challengeVal), &sig); err != nil {
		http.Error(w, "Signature verification failed", 401)
		return false, "Signature failed"
	}

	return true, ""
}
func (s *Server) checkHardenedAuth(w http.ResponseWriter, r *http.Request) bool {
	if !s.cfg.HardenedTrustSync {
		return true
	}

	// 1. Check for Host API Key
	if apiKey := r.Header.Get("X-Host-API-Key"); apiKey != "" {
		hash := auth.HashAPIKey(apiKey)
		_, err := s.db.GetHostByAPIKey(hash)
		if err == nil {
			return true
		}
	}

	// 2. Check for User API Key
	if apiKey := r.Header.Get("X-API-Key"); apiKey != "" {
		hash := auth.HashAPIKey(apiKey)
		_, err := s.db.GetUserByAPIKey(hash)
		if err == nil {
			return true
		}
	}

	// 3. Also allow authenticated web sessions
	if s.authenticate(r) != "" {
		return true
	}

	http.Error(w, "Unauthorized (Hardened Trust Sync enabled)", 401)
	return false
}
