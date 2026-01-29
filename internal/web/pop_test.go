package web

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/SecareLupus/Fenrir_Homelab_SSH_CA/internal/auth"
	"golang.org/x/crypto/ssh"
)

func TestPoPRenewal(t *testing.T) {
	s := setupServer(t)
	d := s.db

	// 1. Setup: Register a Host
	// Generate host key
	_, priv, _ := ed25519.GenerateKey(rand.Reader)
	signer, _ := ssh.NewSignerFromKey(priv)
	pub := signer.PublicKey()
	pubBytes := ssh.MarshalAuthorizedKey(pub)
	fingerprint := ssh.FingerprintSHA256(pub)

	// Register it
	// RegisterHost(hostname, fingerprint string) error
	if err := d.RegisterHost("test-host", fingerprint); err != nil {
		t.Fatalf("failed to register host: %v", err)
	}

	// Set API Key (using "test-key" salt from setupServer)
	apiKey := "test-api-key"
	keyHash := auth.HashAPIKey(apiKey, []byte("test-key"))
	if err := d.SetHostAPIKey("test-host", keyHash); err != nil {
		t.Fatalf("failed to set host api key: %v", err)
	}

	// 2. Attempt Renewal NO Auth
	form := url.Values{}
	form.Add("pubkey", string(pubBytes))
	reqNoAuth := httptest.NewRequest("POST", "/api/v1/host/renew", strings.NewReader(form.Encode()))
	reqNoAuth.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	wNoAuth := httptest.NewRecorder()
	s.handleAPIHostRenew(wNoAuth, reqNoAuth)

	// Expect 401 and Challenge
	if wNoAuth.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401 Unauthorized, got %d. Body: %s", wNoAuth.Code, wNoAuth.Body.String())
	}
	challenge := wNoAuth.Header().Get("X-SSH-Challenge")
	if challenge == "" {
		t.Fatal("expected X-SSH-Challenge header")
	}

	// 3. Sign Challenge
	// verifyPoP verifies the signature over the challenge VALUE (string) as bytes.
	// If challenge is just a random string, we sign its bytes.
	// (Note: In implementation, s.setPoPChallenge stores 'val' and sends 'val' to client)
	sig, err := signer.Sign(rand.Reader, []byte(challenge))
	if err != nil {
		t.Fatalf("sign failed: %v", err)
	}
	sigBase64 := base64.StdEncoding.EncodeToString(ssh.Marshal(sig))

	// 4. Attempt Renewal WITH Auth
	reqAuth := httptest.NewRequest("POST", "/api/v1/host/renew", strings.NewReader(form.Encode()))
	reqAuth.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	reqAuth.Header.Set("X-SSH-Challenge", challenge)
	reqAuth.Header.Set("X-SSH-Signature", sigBase64)

	wAuth := httptest.NewRecorder()
	s.handleAPIHostRenew(wAuth, reqAuth)

	if wAuth.Code != http.StatusOK {
		t.Fatalf("expected 200 OK, got %d. Body: %s", wAuth.Code, wAuth.Body.String())
	}

	// 5. Verify Cert
	certBytes := wAuth.Body.Bytes()
	pubKeyParsed, _, _, _, err := ssh.ParseAuthorizedKey(certBytes)
	if err != nil {
		t.Fatalf("failed to parse returned cert: %v", err)
	}
	cert, ok := pubKeyParsed.(*ssh.Certificate)
	if !ok {
		t.Fatal("returned key is not a certificate")
	}
	if len(cert.ValidPrincipals) == 0 || cert.ValidPrincipals[0] != "test-host" {
		t.Errorf("expected principal test-host, got %v", cert.ValidPrincipals)
	}
}
