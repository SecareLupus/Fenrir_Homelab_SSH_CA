/*
 * Copyright (c) 2026 SecareLupus
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 */

package web

import (
	"context"
	"crypto/hmac"
	"fmt"
	"html/template"
	"log"
	"net/http"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/SecareLupus/Fenrir_Homelab_SSH_CA/internal/auth"
	"github.com/SecareLupus/Fenrir_Homelab_SSH_CA/internal/ca"
	"github.com/SecareLupus/Fenrir_Homelab_SSH_CA/internal/config"
	"github.com/SecareLupus/Fenrir_Homelab_SSH_CA/internal/db"

	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"

	"github.com/xlzd/gotp"
	"golang.org/x/crypto/ssh"

	"regexp"

	"github.com/coreos/go-oidc/v3/oidc"
	"github.com/go-webauthn/webauthn/webauthn"
	"golang.org/x/oauth2"
)

const (
	sessionCookieName   = "session_user"
	oidcStateCookieName = "oidc_state"
)

var principalRegex = regexp.MustCompile(`^[a-zA-Z0-9\\._\\-]+$`)

type Server struct {
	cfg  *config.Config
	db   *db.DB
	ca   *ca.Service
	mux  *http.ServeMux
	tmpl *template.Template
	// challenges stores active PoP challenges: fingerprint -> {challenge, expiry}
	challenges   map[string]challenge
	challengesMu sync.Mutex

	// Metrics
	metricUserCertsSigned uint64
	metricHostCertsSigned uint64

	oidcProvider *oidc.Provider
	oidcConfig   oauth2.Config

	webauthn *webauthn.WebAuthn
	// webauthnSessions stores session data during registration/login: username -> sessionData
	webauthnSessions   map[string]*webauthn.SessionData
	webauthnSessionsMu sync.Mutex

	sessionSecret []byte
	rateLimiter   *rateLimiter
}

type challenge struct {
	val     string
	expires time.Time
}

type sessionData struct {
	Username string `json:"username"`
	Expires  int64  `json:"expires"`
	CSRF     string `json:"csrf"`
}

type oidcStateData struct {
	State   string `json:"state"`
	Nonce   string `json:"nonce"`
	Expires int64  `json:"expires"`
}

func NewServer(cfg *config.Config, db *db.DB, ca *ca.Service) *Server {
	s := &Server{
		cfg:              cfg,
		db:               db,
		ca:               ca,
		mux:              http.NewServeMux(),
		challenges:       make(map[string]challenge),
		webauthnSessions: make(map[string]*webauthn.SessionData),
		rateLimiter:      newRateLimiter(),
	}
	if len(cfg.SessionSecret) > 0 {
		s.sessionSecret = []byte(cfg.SessionSecret)
	} else if len(cfg.DBEncryptionKey) > 0 {
		s.sessionSecret = []byte(cfg.DBEncryptionKey)
	} else {
		if cfg.Production {
			log.Fatalf("FATAL: SESSION_SECRET must be set in production mode")
		}
		secret := make([]byte, 32)
		if _, err := rand.Read(secret); err != nil {
			log.Fatalf("failed to generate session secret: %v", err)
		} else {
			s.sessionSecret = secret
			log.Printf("WARNING: SESSION_SECRET not set; using ephemeral in-memory secret. Sessions will be invalidated on restart.")
		}
	}
	if cfg.OIDC.Enabled {
		provider, err := oidc.NewProvider(context.Background(), cfg.OIDC.IssuerURL)
		if err != nil {
			log.Printf("failed to initialize OIDC provider: %v", err)
		} else {
			s.oidcProvider = provider
			s.oidcConfig = oauth2.Config{
				ClientID:     cfg.OIDC.ClientID,
				ClientSecret: cfg.OIDC.ClientSecret,
				Endpoint:     provider.Endpoint(),
				RedirectURL:  cfg.OIDC.RedirectURL,
				Scopes:       []string{oidc.ScopeOpenID, "profile", "email"},
			}
		}
	}

	w, err := webauthn.New(&webauthn.Config{
		RPDisplayName: cfg.WebAuthn.RPDisplayName,
		RPID:          cfg.WebAuthn.RPID,
		RPOrigins:     []string{cfg.WebAuthn.RPOrigin},
	})
	if err != nil {
		log.Printf("failed to initialize WebAuthn: %v", err)
	} else {
		s.webauthn = w
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
	// Add global version to data
	if m, ok := data.(map[string]any); ok {
		m["Version"] = config.Version
	}

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
	s.mux.HandleFunc("/login/oidc", s.handleLoginOIDC)
	s.mux.HandleFunc("/login/oidc/callback", s.handleLoginOIDCCallback)
	s.mux.HandleFunc("/login/mfa", s.handleLoginMFA)

	s.mux.HandleFunc("/webauthn/register/begin", s.handleWebAuthnRegisterBegin)
	s.mux.HandleFunc("/webauthn/register/finish", s.handleWebAuthnRegisterFinish)
	s.mux.HandleFunc("/webauthn/login/begin", s.handleWebAuthnLoginBegin)
	s.mux.HandleFunc("/webauthn/login/finish", s.handleWebAuthnLoginFinish)

	s.mux.HandleFunc("/logout", s.handleLogout)
	s.mux.HandleFunc("/mfa/setup", s.handleMFASetup)
	s.mux.HandleFunc("/cert/request", s.handleCertRequest)
	s.mux.HandleFunc("/api/keys/generate", s.handleAPIKeyGenerate)
	s.mux.HandleFunc("/api/auth/login", s.handleAPIAuthLogin)
	s.mux.HandleFunc("/admin/users", s.handleAdminUsers)
	s.mux.HandleFunc("/admin/users/toggle", s.handleAdminUserToggle)
	s.mux.HandleFunc("/admin/audit", s.handleAdminAudit)
	s.mux.HandleFunc("/admin/audit/identity", s.handleAdminAuditIdentity)
	s.mux.HandleFunc("/admin/hosts/sign", s.handleAdminHostSign)
	s.mux.HandleFunc("/admin/hosts/apikey", s.handleAdminHostAPIKey)
	s.mux.HandleFunc("/admin/revoke", s.handleAdminRevoke)
	s.mux.HandleFunc("/admin/offline", s.handleAdminOffline)
	s.mux.HandleFunc("/admin/offline/sign", s.handleAdminOfflineSign)
	s.mux.HandleFunc("/admin/hosts", s.handleAdminHosts)
	s.mux.HandleFunc("/admin/hosts/delete", s.handleAdminHostsDelete)
	s.mux.HandleFunc("/admin/groups", s.handleAdminGroups)
	s.mux.HandleFunc("/admin/groups/create", s.handleAdminGroupsCreate)
	s.mux.HandleFunc("/admin/groups/delete", s.handleAdminGroupsDelete)
	s.mux.HandleFunc("/admin/groups/members/toggle", s.handleAdminGroupsMemberToggle)
	s.mux.HandleFunc("/admin/groups/ttl", s.handleAdminGroupsTTL)
	s.mux.HandleFunc("/admin/users/ttl", s.handleAdminUsersTTL)
	s.mux.HandleFunc("/krl", s.handleKRL)
	s.mux.HandleFunc("/api/v1/ca/user", s.handleAPIUserCA)
	s.mux.HandleFunc("/api/v1/ca/host", s.handleAPIHostCA)
	s.mux.HandleFunc("/api/v1/host/renew", s.handleAPIHostRenew)
	s.mux.HandleFunc("/api/v1/health", s.handleHealth)
	s.mux.HandleFunc("/metrics", s.handleMetrics)
	s.mux.HandleFunc("/docs", s.handleDocs)
	s.mux.HandleFunc("/docs/openapi.yaml", s.handleOpenAPI)
}

func (s *Server) Start() error {
	return http.ListenAndServe(s.cfg.BindAddr, s.mux)
}

func (s *Server) handleLogin(w http.ResponseWriter, r *http.Request) {
	if r.Method == "GET" {
		s.renderPage(w, "login.html", map[string]any{"OIDCEnabled": s.cfg.OIDC.Enabled})
		return
	}

	username := r.FormValue("username")
	password := r.FormValue("password")

	if !s.rateLimiter.allow(r.RemoteAddr) {
		log.Printf("Rate limit hit for %s", r.RemoteAddr)
		s.renderPage(w, "login.html", map[string]any{"Error": "Too many attempts. Please try again in a few minutes."})
		return
	}

	// 1. Check if ANY user exists (bootstrapping logic)
	_, err := s.db.GetUserHash("admin")
	if err != nil {
		// If admin doesn't exist, check INITIAL_ADMIN_PASSWORD
		if username == "admin" {
			if s.cfg.InitialAdminPassword == "" {
				log.Printf("Bootstrapping BLOCKED: Admin user doesn't exist and INITIAL_ADMIN_PASSWORD is not set.")
				s.renderPage(w, "login.html", map[string]any{"Error": "Bootstrapping required. Set INITIAL_ADMIN_PASSWORD to create the admin account."})
				return
			}

			if password == s.cfg.InitialAdminPassword {
				hash, _ := auth.HashPassword(password)
				if err := s.db.CreateUser("admin", hash); err == nil {
					_ = s.db.SetUserEnabled("admin", true)
					_, _ = s.db.Exec("UPDATE users SET role = 'admin' WHERE username = 'admin'")
					log.Printf("Bootstrapped admin user successfully using INITIAL_ADMIN_PASSWORD")
				} else {
					log.Printf("Failed to bootstrap admin: %v", err)
				}
			} else {
				log.Printf("Attempted bootstrap with WRONG INITIAL_ADMIN_PASSWORD")
				s.renderPage(w, "login.html", map[string]any{"Error": "Invalid initial admin password."})
				return
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
			Secure:   s.isSecure(r),
			Expires:  time.Now().Add(5 * time.Minute),
		})
		http.Redirect(w, r, "/login/mfa", http.StatusSeeOther)
		return
	}

	// 4. Success - Set Session Cookie
	if err := s.setSession(w, r, username); err != nil {
		http.Error(w, "Failed to create session", 500)
		return
	}
	http.Redirect(w, r, "/", http.StatusSeeOther)
}

func randomToken(size int) (string, error) {
	buf := make([]byte, size)
	if _, err := rand.Read(buf); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(buf), nil
}

func (s *Server) signValue(payload []byte) string {
	payloadB64 := base64.RawURLEncoding.EncodeToString(payload)
	mac := hmac.New(sha256.New, s.sessionSecret)
	mac.Write([]byte(payloadB64))
	sig := mac.Sum(nil)
	sigB64 := base64.RawURLEncoding.EncodeToString(sig)
	return payloadB64 + "." + sigB64
}

func (s *Server) verifyValue(value string) ([]byte, bool) {
	parts := strings.Split(value, ".")
	if len(parts) != 2 {
		return nil, false
	}
	payloadB64 := parts[0]
	sigB64 := parts[1]

	payload, err := base64.RawURLEncoding.DecodeString(payloadB64)
	if err != nil {
		return nil, false
	}
	sig, err := base64.RawURLEncoding.DecodeString(sigB64)
	if err != nil {
		return nil, false
	}

	mac := hmac.New(sha256.New, s.sessionSecret)
	mac.Write([]byte(payloadB64))
	expected := mac.Sum(nil)
	if !hmac.Equal(sig, expected) {
		return nil, false
	}
	return payload, true
}

func (s *Server) signJSON(value any) (string, error) {
	payload, err := json.Marshal(value)
	if err != nil {
		return "", err
	}
	return s.signValue(payload), nil
}

func (s *Server) verifyJSON(value string, out any) bool {
	payload, ok := s.verifyValue(value)
	if !ok {
		return false
	}
	if err := json.Unmarshal(payload, out); err != nil {
		return false
	}
	return true
}

func (s *Server) setSession(w http.ResponseWriter, r *http.Request, username string) error {
	csrfToken, err := randomToken(32)
	if err != nil {
		return err
	}
	session := sessionData{
		Username: username,
		Expires:  time.Now().Add(24 * time.Hour).Unix(),
		CSRF:     csrfToken,
	}
	cookieValue, err := s.signJSON(session)
	if err != nil {
		return err
	}
	http.SetCookie(w, &http.Cookie{
		Name:     sessionCookieName,
		Value:    cookieValue,
		Path:     "/",
		HttpOnly: true,
		Secure:   s.isSecure(r), // Properly handle HTTPS/Proxy
		SameSite: http.SameSiteLaxMode,
		Expires:  time.Now().Add(24 * time.Hour),
	})
	return nil
}

func (s *Server) isSecure(r *http.Request) bool {
	if r.TLS != nil {
		return true
	}
	if r.Header.Get("X-Forwarded-Proto") == "https" {
		return true
	}
	return false
}

func (s *Server) getSession(r *http.Request) (*sessionData, bool) {
	cookie, err := r.Cookie(sessionCookieName)
	if err != nil || cookie.Value == "" {
		return nil, false
	}
	var session sessionData
	if !s.verifyJSON(cookie.Value, &session) {
		return nil, false
	}
	if session.Username == "" || session.Expires == 0 {
		return nil, false
	}
	if time.Now().Unix() > session.Expires {
		return nil, false
	}
	return &session, true
}

func (s *Server) csrfToken(r *http.Request) string {
	session, ok := s.getSession(r)
	if !ok {
		return ""
	}
	return session.CSRF
}

func (s *Server) requireCSRF(w http.ResponseWriter, r *http.Request) bool {
	// Allow bypassing CSRF if a valid API Key is provided
	if apiKey := r.Header.Get("X-API-Key"); apiKey != "" {
		hash := auth.HashAPIKey(apiKey, s.sessionSecret)
		_, err := s.db.GetUserByAPIKey(hash)
		if err == nil {
			return true
		}
	}

	token := r.Header.Get("X-CSRF-Token")
	if token == "" {
		token = r.FormValue("csrf_token")
	}
	if token == "" {
		http.Error(w, "CSRF token required", 403)
		return false
	}
	session, ok := s.getSession(r)
	if !ok || session.CSRF == "" {
		http.Error(w, "CSRF session invalid", 403)
		return false
	}
	if !hmac.Equal([]byte(token), []byte(session.CSRF)) {
		http.Error(w, "CSRF token invalid", 403)
		return false
	}
	return true
}

func (s *Server) handleLogout(w http.ResponseWriter, r *http.Request) {
	http.SetCookie(w, &http.Cookie{
		Name:     sessionCookieName,
		Value:    "",
		Path:     "/",
		HttpOnly: true,
		MaxAge:   -1,
	})
	http.Redirect(w, r, "/login", http.StatusSeeOther)
}

func (s *Server) handleLoginOIDC(w http.ResponseWriter, r *http.Request) {
	if !s.cfg.OIDC.Enabled || s.oidcProvider == nil {
		http.Error(w, "OIDC is not enabled", 400)
		return
	}

	state, err := randomToken(32)
	if err != nil {
		http.Error(w, "Failed to initialize OIDC state", 500)
		return
	}
	nonce, err := randomToken(32)
	if err != nil {
		http.Error(w, "Failed to initialize OIDC nonce", 500)
		return
	}

	stateCookie, err := s.signJSON(oidcStateData{
		State:   state,
		Nonce:   nonce,
		Expires: time.Now().Add(10 * time.Minute).Unix(),
	})
	if err != nil {
		http.Error(w, "Failed to initialize OIDC state", 500)
		return
	}
	http.SetCookie(w, &http.Cookie{
		Name:     oidcStateCookieName,
		Value:    stateCookie,
		Path:     "/",
		HttpOnly: true,
		Secure:   s.isSecure(r),
		SameSite: http.SameSiteLaxMode,
		Expires:  time.Now().Add(10 * time.Minute),
	})

	url := s.oidcConfig.AuthCodeURL(state, oauth2.SetAuthURLParam("nonce", nonce))
	http.Redirect(w, r, url, http.StatusFound)
}

func (s *Server) handleLoginOIDCCallback(w http.ResponseWriter, r *http.Request) {
	if !s.cfg.OIDC.Enabled || s.oidcProvider == nil {
		http.Error(w, "OIDC is not enabled", 400)
		return
	}

	state := r.URL.Query().Get("state")
	stateCookie, err := r.Cookie(oidcStateCookieName)
	if err != nil || stateCookie.Value == "" {
		http.Error(w, "missing OIDC state", 400)
		return
	}
	var storedState oidcStateData
	if !s.verifyJSON(stateCookie.Value, &storedState) {
		http.Error(w, "invalid OIDC state", 400)
		return
	}
	if time.Now().Unix() > storedState.Expires {
		http.Error(w, "OIDC state expired", 400)
		return
	}
	if state == "" || state != storedState.State {
		http.Error(w, "invalid state", 400)
		return
	}

	code := r.URL.Query().Get("code")
	oauth2Token, err := s.oidcConfig.Exchange(context.Background(), code)
	if err != nil {
		http.Error(w, "Failed to exchange token: "+err.Error(), 500)
		return
	}

	rawIDToken, ok := oauth2Token.Extra("id_token").(string)
	if !ok {
		http.Error(w, "No id_token in token response", 500)
		return
	}

	verifier := s.oidcProvider.Verifier(&oidc.Config{ClientID: s.oidcConfig.ClientID})
	idToken, err := verifier.Verify(context.Background(), rawIDToken)
	if err != nil {
		http.Error(w, "Failed to verify ID Token: "+err.Error(), 500)
		return
	}
	if storedState.Nonce == "" || idToken.Nonce != storedState.Nonce {
		http.Error(w, "invalid nonce", 400)
		return
	}

	http.SetCookie(w, &http.Cookie{
		Name:     oidcStateCookieName,
		Value:    "",
		Path:     "/",
		HttpOnly: true,
		MaxAge:   -1,
	})

	var claims struct {
		Email string `json:"email"`
	}
	if err := idToken.Claims(&claims); err != nil {
		http.Error(w, "Failed to parse claims: "+err.Error(), 500)
		return
	}

	username := claims.Email
	if username == "" {
		http.Error(w, "No email in OIDC claims", 400)
		return
	}

	// Upsert user if enabled
	_, err = s.db.GetUserHash(username)
	if err != nil {
		// Create user with a random password if they don't exist
		// Since they authenticated via OIDC, we just need a record.
		err = s.db.CreateUser(username, "OIDC_EXTERNAL_USER")
		if err == nil {
			_ = s.db.SetUserEnabled(username, true)
		}
	}

	if !s.db.IsUserEnabled(username) {
		http.Error(w, "User account disabled", 403)
		return
	}

	if err := s.setSession(w, r, username); err != nil {
		http.Error(w, "Failed to create session", 500)
		return
	}
	http.Redirect(w, r, "/", http.StatusSeeOther)
}

func (s *Server) authenticate(r *http.Request) string {
	// 1. Check for API Key in header
	apiKey := r.Header.Get("X-API-Key")
	if apiKey != "" {
		hash := auth.HashAPIKey(apiKey, s.sessionSecret)
		username, err := s.db.GetUserByAPIKey(hash)
		if err == nil {
			return username
		}
	}

	// 2. Check for Session Cookie
	session, ok := s.getSession(r)
	if ok {
		return session.Username
	}

	return ""
}

func (s *Server) isAdmin(username string) bool {
	if username == "" {
		return false
	}
	role, err := s.db.GetUserRole(username)
	if err != nil {
		return false
	}
	return role == "admin"
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
		"IsAdmin":   s.isAdmin(username),
		"UserCAKey": string(userCA),
		"HostCAKey": string(hostCA),
		"Mode":      s.cfg.Mode,
	}
	s.renderPage(w, "dashboard.html", data)
}

func (s *Server) handleAdminOffline(w http.ResponseWriter, r *http.Request) {
	username := s.authenticate(r)
	if !s.isAdmin(username) {
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
	s.attachCSRFToken(r, data)
	s.renderPage(w, "admin_offline.html", data)
}

func (s *Server) handleAdminOfflineSign(w http.ResponseWriter, r *http.Request) {
	if r.Method != "POST" {
		http.Redirect(w, r, "/admin/offline", http.StatusSeeOther)
		return
	}

	username := s.authenticate(r)
	if !s.isAdmin(username) {
		http.Error(w, "Forbidden", 403)
		return
	}
	if !s.requireCSRF(w, r) {
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

	// 1.5 Check for Revocation
	if s.db.IsPublicKeyRevoked(fingerprint) {
		log.Printf("Blocked certificate request for revoked key: %s", fingerprint)
		http.Error(w, "This public key has been revoked and cannot be used for new certificates.", 403)
		return
	}

	// 2. Authentication Decision
	// Priority 1: Active Web Session or API Key in Header
	username = s.authenticate(r)
	if username != "" {
		// Verify ownership: key must be either new or owned by this user
		owner, err := s.db.CheckPublicKeyOwnership(fingerprint)
		if err == nil {
			if owner != username {
				http.Error(w, "Public key is registered to another user", 403)
				return
			}
		} else {
			// Key not registered, this will be an auto-enrollment
			isNewKey = true
		}
	} else {
		// Priority 2: Extension/CLI Renewal via PoP (Proof of Possession)
		owner, err := s.db.CheckPublicKeyOwnership(fingerprint)
		if err != nil {
			log.Printf("Unauthenticated enrollment attempt for key %s", fingerprint)
			http.Error(w, "Key not enrolled. Please login or provide an API Key.", 401)
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

	// 2.5 Extract and validate Principals
	principalsStr := r.FormValue("principals")

	// Default principals: username + "pi" + all user's groups
	principals := []string{username, "pi"}
	groups, _ := s.db.GetUserGroups(username)
	principals = append(principals, groups...)

	// Logic: Admins can override, normal users are restricted for safety
	if s.isAdmin(username) && principalsStr != "" {
		parts := strings.Split(principalsStr, ",")
		var cleanParts []string
		for _, p := range parts {
			trimmed := strings.TrimSpace(p)
			if trimmed != "" {
				if !principalRegex.MatchString(trimmed) {
					http.Error(w, "Invalid principal format: "+trimmed, 400)
					return
				}
				cleanParts = append(cleanParts, trimmed)
			}
		}
		if len(cleanParts) > 0 {
			principals = cleanParts
		}
	}

	// Double check user is still enabled
	if !s.db.IsUserEnabled(username) {
		http.Error(w, "User account disabled", 403)
		return
	}

	// 3. Register Key if new
	if isNewKey {
		uid, _ := s.db.GetUserID(username)
		comment := "Enrolled via WebUI"
		if r.Header.Get("X-API-Key") != "" {
			comment = "Enrolled via API"
		}
		s.db.RegisterPublicKey(uid, fingerprint, pubKey.Type(), pubKeyStr, comment)
		s.db.LogEvent(&uid, "key_enrolled", fingerprint)
	}

	// 4. Sign Certificate
	ttl, _ := strconv.ParseUint(ttlStr, 10, 64)
	if ttl == 0 {
		ttl = 3600
	}

	// Resolve Policy Max TTL
	maxTTL, _ := s.db.GetMaxTTL(username)
	if maxTTL > 0 && uint64(maxTTL) < ttl {
		ttl = uint64(maxTTL)
	}

	if ttl > 86400 {
		ttl = 86400
	}

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
	hash := auth.HashAPIKey(apiKey, s.sessionSecret)

	if err := s.db.CreateAPIKey(userId, hash, "Default Key"); err != nil {
		log.Printf("Error storing API key: %v", err)
		http.Error(w, "Failed to store key", 500)
		return
	}

	// For MVP, we'll just show the key once in a simple page or redirected param.
	// Properly, this should be a flash message or a specific "key created" view.
	s.renderPage(w, "dashboard.html", map[string]any{
		"User":      username,
		"IsAdmin":   s.isAdmin(username),
		"NewAPIKey": apiKey,
		"UserCAKey": string(ssh.MarshalAuthorizedKey(s.ca.GetUserCAPublicKey())),
		"HostCAKey": string(ssh.MarshalAuthorizedKey(s.ca.GetHostCAPublicKey())),
	})
}

// handleAPIAuthLogin authenticates a CLI client via username/password and returns an API key
func (s *Server) handleAPIAuthLogin(w http.ResponseWriter, r *http.Request) {
	if r.Method != "POST" {
		http.Error(w, "Method not allowed", 405)
		return
	}

	var req struct {
		Username string `json:"username"`
		Password string `json:"password"`
		TOTPCode string `json:"totp_code,omitempty"`
	}

	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Invalid request body", 400)
		return
	}

	// 1. Validate username and password
	hash, err := s.db.GetUserHash(req.Username)
	if err != nil || !auth.CheckPassword(req.Password, hash) {
		http.Error(w, "Invalid credentials", 401)
		return
	}

	// 2. Check if user is enabled
	if !s.db.IsUserEnabled(req.Username) {
		http.Error(w, "User account disabled", 403)
		return
	}

	// 3. Check MFA if enabled
	mfaSecret, _ := s.db.GetUserMFASecret(req.Username)
	if mfaSecret != "" {
		if req.TOTPCode == "" {
			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(map[string]any{
				"error":        "MFA required",
				"mfa_required": true,
			})
			return
		}

		// Verify TOTP
		totp := gotp.NewDefaultTOTP(mfaSecret)
		if !totp.Verify(req.TOTPCode, time.Now().Unix()) {
			// Check backup codes
			hash := auth.HashAPIKey(req.TOTPCode, s.sessionSecret) // Using same hash as API keys
			valid, _ := s.db.VerifyBackupCode(req.Username, hash)
			if !valid {
				http.Error(w, "Invalid MFA code", 401)
				return
			}
		}
	}

	// 4. Generate API key
	userId, err := s.db.GetUserID(req.Username)
	if err != nil {
		http.Error(w, "User not found", 404)
		return
	}

	rawKey := make([]byte, 32)
	if _, err := rand.Read(rawKey); err != nil {
		http.Error(w, "Key generation failed", 500)
		return
	}
	apiKey := hex.EncodeToString(rawKey)
	keyHash := auth.HashAPIKey(apiKey, s.sessionSecret)

	if err := s.db.CreateAPIKey(userId, keyHash, "CLI Generated Key"); err != nil {
		log.Printf("Error storing API key: %v", err)
		http.Error(w, "Failed to store key", 500)
		return
	}

	// 5. Log the event
	s.db.LogEvent(&userId, "api_key_cli_generated", "Generated via CLI login")

	// 6. Return the API key
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{
		"api_key": apiKey,
		"message": "Successfully authenticated. Store this key securely.",
	})
}

// renderPage helps avoid block collisions by parsing layout + page on fly (dev friendly)
// or cloning/re-associating (prod friendly).
// For this scale, parsing on fly is fine and easiest for avoiding "content" collisions.
func (s *Server) renderPage(w http.ResponseWriter, page string, data any) {
	// Add global version to data
	if m, ok := data.(map[string]any); ok {
		m["Version"] = config.Version
	} else if data == nil {
		data = map[string]any{"Version": config.Version}
	}

	allowed := map[string]bool{
		"login.html":                true,
		"dashboard.html":            true,
		"admin_offline.html":        true,
		"admin_users.html":          true,
		"admin_audit.html":          true,
		"admin_audit_identity.html": true,
		"admin_host_sign.html":      true,
		"admin_host_apikey.html":    true,
		"admin_groups.html":         true,
		"login_mfa.html":            true,
		"mfa_setup.html":            true,
		"mfa_backup_codes.html":     true,
		"admin_hosts.html":          true,
	}
	if !allowed[page] {
		log.Printf("Blocked template traversal attempt: %s", page)
		http.Error(w, "Invalid template", 400)
		return
	}

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

func (s *Server) attachCSRFToken(r *http.Request, data map[string]any) {
	if data == nil {
		return
	}
	if token := s.csrfToken(r); token != "" {
		data["CSRFToken"] = token
	}
}

func (s *Server) handleAdminUsers(w http.ResponseWriter, r *http.Request) {
	username := s.authenticate(r)
	if !s.isAdmin(username) {
		http.Error(w, "Forbidden", 403)
		return
	}

	users, err := s.db.ListUsers()
	if err != nil {
		http.Error(w, err.Error(), 500)
		return
	}

	data := map[string]any{
		"User":  username,
		"Users": users,
	}
	s.attachCSRFToken(r, data)
	s.renderPage(w, "admin_users.html", data)
}

func (s *Server) handleAdminUserToggle(w http.ResponseWriter, r *http.Request) {
	if r.Method != "POST" {
		http.Redirect(w, r, "/admin/users", http.StatusSeeOther)
		return
	}

	admin := s.authenticate(r)
	if !s.isAdmin(admin) {
		http.Error(w, "Forbidden", 403)
		return
	}
	if !s.requireCSRF(w, r) {
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
	if !s.isAdmin(username) {
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
	if !s.isAdmin(username) {
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
	if !s.isAdmin(username) {
		http.Error(w, "Forbidden", 403)
		return
	}

	if r.Method == "GET" {
		hosts, _ := s.db.ListHosts()
		data := map[string]any{
			"User":  username,
			"Hosts": hosts,
		}
		s.attachCSRFToken(r, data)
		s.renderPage(w, "admin_host_sign.html", data)
		return
	}

	// POST: Sign Host Key
	if !s.requireCSRF(w, r) {
		return
	}
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

	// Parse principals from comma-separated hostname field
	parts := strings.Split(hostname, ",")
	var principals []string
	for _, p := range parts {
		trimmed := strings.TrimSpace(p)
		if trimmed != "" {
			if !principalRegex.MatchString(trimmed) {
				http.Error(w, "Invalid hostname/principal format: "+trimmed, 400)
				return
			}
			principals = append(principals, trimmed)
		}
	}
	if len(principals) == 0 {
		http.Error(w, "Hostname/Principals required", 400)
		return
	}

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
	if r.Method != "POST" {
		http.Error(w, "Method not allowed", 405)
		return
	}

	username := s.authenticate(r)
	if !s.isAdmin(username) {
		http.Error(w, "Forbidden", 403)
		return
	}
	if !s.requireCSRF(w, r) {
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

	hash := auth.HashAPIKey(apiKey, s.sessionSecret)
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
	if !s.isAdmin(username) {
		http.Error(w, "Forbidden", 403)
		return
	}
	if !s.requireCSRF(w, r) {
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

func (s *Server) handleAdminGroups(w http.ResponseWriter, r *http.Request) {
	username := s.authenticate(r)
	if !s.isAdmin(username) {
		http.Error(w, "Forbidden", 403)
		return
	}

	groups, err := s.db.ListGroups()
	if err != nil {
		http.Error(w, err.Error(), 500)
		return
	}

	users, _ := s.db.ListUsers()

	// Build a map of group name -> members for easier rendering
	groupMembers := make(map[string][]string)
	for _, g := range groups {
		// This is a bit inefficient (N queries), but fine for small homelab scale
		members, _ := s.db.GetUserGroupsByGroupName(g.Name)
		groupMembers[g.Name] = members
	}

	data := map[string]any{
		"User":         username,
		"Groups":       groups,
		"Users":        users,
		"GroupMembers": groupMembers,
	}
	s.attachCSRFToken(r, data)
	s.renderPage(w, "admin_groups.html", data)
}

func (s *Server) handleAdminGroupsCreate(w http.ResponseWriter, r *http.Request) {
	if r.Method != "POST" {
		http.Redirect(w, r, "/admin/groups", http.StatusSeeOther)
		return
	}

	admin := s.authenticate(r)
	if !s.isAdmin(admin) {
		http.Error(w, "Forbidden", 403)
		return
	}
	if !s.requireCSRF(w, r) {
		return
	}

	name := r.FormValue("name")
	desc := r.FormValue("description")

	if err := s.db.CreateGroup(name, desc); err != nil {
		http.Error(w, err.Error(), 500)
		return
	}

	uid, _ := s.db.GetUserID(admin)
	s.db.LogEvent(&uid, "group_created", name)

	http.Redirect(w, r, "/admin/groups", http.StatusSeeOther)
}

func (s *Server) handleAdminGroupsDelete(w http.ResponseWriter, r *http.Request) {
	if r.Method != "POST" {
		http.Redirect(w, r, "/admin/groups", http.StatusSeeOther)
		return
	}

	admin := s.authenticate(r)
	if !s.isAdmin(admin) {
		http.Error(w, "Forbidden", 403)
		return
	}
	if !s.requireCSRF(w, r) {
		return
	}

	name := r.FormValue("name")

	if err := s.db.DeleteGroup(name); err != nil {
		http.Error(w, err.Error(), 500)
		return
	}

	uid, _ := s.db.GetUserID(admin)
	s.db.LogEvent(&uid, "group_deleted", name)

	http.Redirect(w, r, "/admin/groups", http.StatusSeeOther)
}

func (s *Server) handleAdminGroupsMemberToggle(w http.ResponseWriter, r *http.Request) {
	if r.Method != "POST" {
		http.Redirect(w, r, "/admin/groups", http.StatusSeeOther)
		return
	}

	admin := s.authenticate(r)
	if !s.isAdmin(admin) {
		http.Error(w, "Forbidden", 403)
		return
	}
	if !s.requireCSRF(w, r) {
		return
	}

	username := r.FormValue("username")
	groupName := r.FormValue("group")
	action := r.FormValue("action") // "add" or "remove"

	var err error
	if action == "add" {
		err = s.db.AddUserToGroup(username, groupName)
	} else {
		err = s.db.RemoveUserFromGroup(username, groupName)
	}

	if err != nil {
		http.Error(w, err.Error(), 500)
		return
	}

	uid, _ := s.db.GetUserID(admin)
	s.db.LogEvent(&uid, "group_membership_updated", fmt.Sprintf("%s:%s:%s", groupName, username, action))

	http.Redirect(w, r, "/admin/groups", http.StatusSeeOther)
}

func (s *Server) handleAdminGroupsTTL(w http.ResponseWriter, r *http.Request) {
	if r.Method != "POST" {
		http.Redirect(w, r, "/admin/groups", http.StatusSeeOther)
		return
	}

	admin := s.authenticate(r)
	if !s.isAdmin(admin) {
		http.Error(w, "Forbidden", 403)
		return
	}
	if !s.requireCSRF(w, r) {
		return
	}

	name := r.FormValue("name")
	ttlStr := r.FormValue("ttl")
	ttl, _ := strconv.Atoi(ttlStr)

	if err := s.db.SetGroupMaxTTL(name, ttl); err != nil {
		http.Error(w, err.Error(), 500)
		return
	}

	uid, _ := s.db.GetUserID(admin)
	s.db.LogEvent(&uid, "group_ttl_updated", fmt.Sprintf("%s:%d", name, ttl))

	http.Redirect(w, r, "/admin/groups", http.StatusSeeOther)
}

func (s *Server) handleAdminUsersTTL(w http.ResponseWriter, r *http.Request) {
	if r.Method != "POST" {
		http.Redirect(w, r, "/admin/users", http.StatusSeeOther)
		return
	}

	admin := s.authenticate(r)
	if !s.isAdmin(admin) {
		http.Error(w, "Forbidden", 403)
		return
	}
	if !s.requireCSRF(w, r) {
		return
	}

	username := r.FormValue("username")
	ttlStr := r.FormValue("ttl")
	ttl, _ := strconv.Atoi(ttlStr)

	if err := s.db.SetUserMaxTTL(username, ttl); err != nil {
		http.Error(w, err.Error(), 500)
		return
	}

	uid, _ := s.db.GetUserID(admin)
	s.db.LogEvent(&uid, "user_ttl_updated", fmt.Sprintf("%s:%d", username, ttl))

	http.Redirect(w, r, "/admin/users", http.StatusSeeOther)
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
		hash := auth.HashAPIKey(code, s.sessionSecret) // Using same hash as API keys
		valid, _ = s.db.VerifyBackupCode(username, hash)
	}

	if valid {
		// Clear pending cookie
		http.SetCookie(w, &http.Cookie{Name: "mfa_pending_user", MaxAge: -1, Path: "/"})
		if err := s.setSession(w, r, username); err != nil {
			http.Error(w, "Failed to create session", 500)
			return
		}
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
		hashedCodes = append(hashedCodes, auth.HashAPIKey(plain, s.sessionSecret))
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

func (s *Server) handleMetrics(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/plain; version=0.0.4")
	fmt.Fprintf(w, "# HELP ssh_ca_user_certs_signed_total Total number of user certificates signed\n")
	fmt.Fprintf(w, "# TYPE ssh_ca_user_certs_signed_total counter\n")
	fmt.Fprintf(w, "ssh_ca_user_certs_signed_total %d\n", atomic.LoadUint64(&s.metricUserCertsSigned))

	fmt.Fprintf(w, "# HELP ssh_ca_host_certs_signed_total Total number of host certificates signed\n")
	fmt.Fprintf(w, "# TYPE ssh_ca_host_certs_signed_total counter\n")
	fmt.Fprintf(w, "ssh_ca_host_certs_signed_total %d\n", atomic.LoadUint64(&s.metricHostCertsSigned))
}

func (s *Server) handleOpenAPI(w http.ResponseWriter, r *http.Request) {
	http.ServeFile(w, r, "docs/openapi.yaml")
}

func (s *Server) handleDocs(w http.ResponseWriter, r *http.Request) {
	html := `
<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="utf-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1" />
  <meta name="description" content="SSH CA API Documentation" />
  <title>SSH CA | API Docs</title>
  <link rel="stylesheet" href="https://unpkg.com/swagger-ui-dist@5.11.0/swagger-ui.css" />
</head>
<body>
  <div id="swagger-ui"></div>
  <script src="https://unpkg.com/swagger-ui-dist@5.11.0/swagger-ui-bundle.js" crossorigin></script>
  <script>
    window.onload = () => {
      window.ui = SwaggerUIBundle({
        url: '/docs/openapi.yaml',
        dom_id: '#swagger-ui',
      });
    };
  </script>
</body>
</html>`
	w.Header().Set("Content-Type", "text/html")
	w.Write([]byte(html))
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
		hash := auth.HashAPIKey(apiKey, s.sessionSecret)
		hostname, err = s.db.GetHostByAPIKey(hash)
		if err != nil {
			http.Error(w, "Unauthorized (Invalid API Key)", 401)
			return
		}
		s.db.UpdateHostLastSeen(hostname)
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
		s.db.UpdateHostLastSeen(hostname)
	}

	// Sign the host key
	principals := []string{hostname}
	cert, err := s.ca.SignHostCertificate(pubKey, hostname, principals, 365*24*3600)
	if err != nil {
		log.Printf("host renewal failed for %s: %v", hostname, err)
		http.Error(w, "Internal server error during signing", 500)
		return
	}

	atomic.AddUint64(&s.metricHostCertsSigned, 1)

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
		s.challengesMu.Lock()
		s.challenges[fingerprint] = challenge{val: cStr, expires: time.Now().Add(5 * time.Minute)}
		s.challengesMu.Unlock()

		w.Header().Set("X-SSH-Challenge", cStr)
		http.Error(w, "Proof of Possession required", 401)
		return false, "PoP required"
	}

	// Verify Challenge
	s.challengesMu.Lock()
	stored, ok := s.challenges[fingerprint]
	if !ok || stored.val != challengeVal || time.Now().After(stored.expires) {
		s.challengesMu.Unlock()
		http.Error(w, "Invalid or expired challenge", 401)
		return false, "Invalid challenge"
	}
	delete(s.challenges, fingerprint)
	s.challengesMu.Unlock()

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
		hash := auth.HashAPIKey(apiKey, s.sessionSecret)
		_, err := s.db.GetHostByAPIKey(hash)
		if err == nil {
			return true
		}
	}

	// 2. Check for User API Key
	if apiKey := r.Header.Get("X-API-Key"); apiKey != "" {
		hash := auth.HashAPIKey(apiKey, s.sessionSecret)
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

func (s *Server) handleAdminHosts(w http.ResponseWriter, r *http.Request) {
	username := s.authenticate(r)
	if !s.isAdmin(username) {
		http.Error(w, "Forbidden", 403)
		return
	}

	hosts, err := s.db.ListHosts()
	if err != nil {
		http.Error(w, err.Error(), 500)
		return
	}

	data := map[string]any{
		"User":    username,
		"IsAdmin": true,
		"Hosts":   hosts,
	}
	s.attachCSRFToken(r, data)
	s.renderPage(w, "admin_hosts.html", data)
}

func (s *Server) handleAdminHostsDelete(w http.ResponseWriter, r *http.Request) {
	if r.Method != "POST" {
		http.Redirect(w, r, "/admin/hosts", http.StatusSeeOther)
		return
	}

	admin := s.authenticate(r)
	if !s.isAdmin(admin) {
		http.Error(w, "Forbidden", 403)
		return
	}
	if !s.requireCSRF(w, r) {
		return
	}

	hostname := r.FormValue("hostname")
	if err := s.db.DeleteHost(hostname); err != nil {
		http.Error(w, err.Error(), 500)
		return
	}

	uid, _ := s.db.GetUserID(admin)
	s.db.LogEvent(&uid, "host_deleted", hostname)

	http.Redirect(w, r, "/admin/hosts", http.StatusSeeOther)
}

func (s *Server) handleWebAuthnRegisterBegin(w http.ResponseWriter, r *http.Request) {
	if s.webauthn == nil {
		http.Error(w, "WebAuthn is not configured", 503)
		return
	}
	username := s.authenticate(r)
	if username == "" {
		http.Error(w, "Unauthorized", 401)
		return
	}

	user, err := s.db.GetUser(username)
	if err != nil {
		http.Error(w, "User not found", 404)
		return
	}

	creds, _ := s.db.GetWebAuthnCredentials(username)
	waUser := &webauthnUser{User: user, creds: creds}

	options, sessionData, err := s.webauthn.BeginRegistration(waUser)
	if err != nil {
		http.Error(w, err.Error(), 500)
		return
	}

	s.webauthnSessionsMu.Lock()
	s.webauthnSessions[username] = sessionData
	s.webauthnSessionsMu.Unlock()
	json.NewEncoder(w).Encode(options)
}

func (s *Server) handleWebAuthnRegisterFinish(w http.ResponseWriter, r *http.Request) {
	if s.webauthn == nil {
		http.Error(w, "WebAuthn is not configured", 503)
		return
	}
	username := s.authenticate(r)
	if username == "" {
		http.Error(w, "Unauthorized", 401)
		return
	}

	s.webauthnSessionsMu.Lock()
	sessionData, ok := s.webauthnSessions[username]
	if ok {
		delete(s.webauthnSessions, username)
	}
	s.webauthnSessionsMu.Unlock()
	if !ok {
		http.Error(w, "Session not found", 400)
		return
	}

	user, _ := s.db.GetUser(username)
	creds, _ := s.db.GetWebAuthnCredentials(username)
	waUser := &webauthnUser{User: user, creds: creds}

	credential, err := s.webauthn.FinishRegistration(waUser, *sessionData, r)
	if err != nil {
		http.Error(w, err.Error(), 400)
		return
	}

	err = s.db.AddWebAuthnCredential(username, credential.ID, credential.PublicKey, credential.Authenticator.AAGUID, string(credential.AttestationType), int32(credential.Authenticator.SignCount))
	if err != nil {
		http.Error(w, "Failed to store credential: "+err.Error(), 500)
		return
	}

	w.Write([]byte("Registration successful"))
}

func (s *Server) handleWebAuthnLoginBegin(w http.ResponseWriter, r *http.Request) {
	if s.webauthn == nil {
		http.Error(w, "WebAuthn is not configured", 503)
		return
	}
	username := r.URL.Query().Get("username")
	if username == "" {
		http.Error(w, "Missing username", 400)
		return
	}

	user, err := s.db.GetUser(username)
	if err != nil {
		http.Error(w, "User not found", 404)
		return
	}

	creds, _ := s.db.GetWebAuthnCredentials(username)
	waUser := &webauthnUser{User: user, creds: creds}

	options, sessionData, err := s.webauthn.BeginLogin(waUser)
	if err != nil {
		http.Error(w, err.Error(), 500)
		return
	}

	s.webauthnSessionsMu.Lock()
	s.webauthnSessions[username] = sessionData
	s.webauthnSessionsMu.Unlock()
	json.NewEncoder(w).Encode(options)
}

func (s *Server) handleWebAuthnLoginFinish(w http.ResponseWriter, r *http.Request) {
	if s.webauthn == nil {
		http.Error(w, "WebAuthn is not configured", 503)
		return
	}
	username := r.URL.Query().Get("username")
	if username == "" {
		http.Error(w, "Missing username", 400)
		return
	}

	s.webauthnSessionsMu.Lock()
	sessionData, ok := s.webauthnSessions[username]
	if ok {
		delete(s.webauthnSessions, username)
	}
	s.webauthnSessionsMu.Unlock()
	if !ok {
		http.Error(w, "Session not found", 400)
		return
	}

	user, _ := s.db.GetUser(username)
	creds, _ := s.db.GetWebAuthnCredentials(username)
	waUser := &webauthnUser{User: user, creds: creds}

	credential, err := s.webauthn.FinishLogin(waUser, *sessionData, r)
	if err != nil {
		http.Error(w, err.Error(), 400)
		return
	}

	// Update sign count
	s.db.UpdateWebAuthnCredential(credential.ID, int32(credential.Authenticator.SignCount))

	if err := s.setSession(w, r, username); err != nil {
		http.Error(w, "Failed to create session", 500)
		return
	}
	w.Write([]byte("Login successful"))
}

// --- Rate Limiting ---

type rateLimiter struct {
	attempts map[string][]time.Time
	mu       sync.Mutex
}

func newRateLimiter() *rateLimiter {
	return &rateLimiter{attempts: make(map[string][]time.Time)}
}

func (rl *rateLimiter) allow(key string) bool {
	rl.mu.Lock()
	defer rl.mu.Unlock()
	now := time.Now()
	var newAttempts []time.Time
	for _, t := range rl.attempts[key] {
		if now.Sub(t) < 5*time.Minute {
			newAttempts = append(newAttempts, t)
		}
	}
	if len(newAttempts) >= 10 { // 10 attempts per 5 mins
		rl.attempts[key] = newAttempts
		return false
	}
	rl.attempts[key] = append(newAttempts, now)
	return true
}
