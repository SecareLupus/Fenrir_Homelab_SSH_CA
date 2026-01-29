package web

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/SecareLupus/Fenrir_Homelab_SSH_CA/internal/ca"
	"github.com/SecareLupus/Fenrir_Homelab_SSH_CA/internal/config"
	"github.com/SecareLupus/Fenrir_Homelab_SSH_CA/internal/db"
)

func TestSessionSecretRotation(t *testing.T) {
	d, _ := db.Init(":memory:", "", "test-key")
	tmpDir := t.TempDir()
	caCfg := &config.Config{KeyPath: tmpDir, CAPassphrase: "test"}
	c, _ := ca.New(caCfg)
	cfg := &config.Config{SessionSecret: "initial-secret"}
	srv := NewServer(cfg, d, c)

	// 1. Verify bootstrap
	srv.sessionSecretsMu.RLock()
	if len(srv.sessionSecrets) != 1 {
		t.Fatalf("expected 1 session secret after bootstrap, got %d", len(srv.sessionSecrets))
	}
	initialSecret := srv.sessionSecrets[0].SecretValue
	srv.sessionSecretsMu.RUnlock()

	// 2. Sign a value with initial secret
	payload := []byte("test-session")
	signedValue := srv.signValue(payload)

	// 3. Manually trigger rotation
	// Fake time by updating CreatedAt in DB to be 31 days ago
	d.Exec("UPDATE system_secrets SET created_at = DATETIME('now', '-31 days') WHERE key_type = 'session'")
	srv.syncSessionSecrets() // Load old one into cache for rotate function to see it

	srv.rotateSessionSecretIfNeeded()
	srv.syncSessionSecrets()

	srv.sessionSecretsMu.RLock()
	if len(srv.sessionSecrets) != 2 {
		t.Errorf("expected 2 session secrets after rotation, got %d", len(srv.sessionSecrets))
	}
	newSecret := srv.sessionSecrets[0].SecretValue
	if newSecret == initialSecret {
		t.Errorf("expected secret to change after rotation")
	}
	srv.sessionSecretsMu.RUnlock()

	// 4. Verify rollover: Old signed value should still be valid
	_, ok := srv.verifyValue(signedValue)
	if !ok {
		t.Errorf(" rollover failed: old signed value should still be valid after rotation")
	}

	// 5. Sign new value with new secret
	newSignedValue := srv.signValue(payload)
	_, ok = srv.verifyValue(newSignedValue)
	if !ok {
		t.Errorf("new secret failed to verify new signed value")
	}

	// 6. Verify expiration: Set old secret to expired
	d.Exec("UPDATE system_secrets SET expires_at = DATETIME('now', '-1 hour') WHERE secret_value = ?", initialSecret)
	srv.syncSessionSecrets()

	_, ok = srv.verifyValue(signedValue)
	if ok {
		t.Errorf("expired secret should no longer verify values")
	}
}

func TestCARotation(t *testing.T) {
	d, _ := db.Init(":memory:", "", "test-key")
	tmpDir := t.TempDir()
	caCfg := &config.Config{KeyPath: tmpDir, CAPassphrase: "test"}
	c, _ := ca.New(caCfg)
	srv := NewServer(caCfg, d, c)

	// 1. Initial bundle size
	bundle := srv.ca.GetUserCAPublicBundle()
	if len(bundle) != 1 {
		t.Errorf("expected 1 CA key initially, got %d", len(bundle))
	}

	// 2. Trigger rotation
	srv.rotateCAIfNeeded() // First call bootstraps metadata
	d.Exec("UPDATE system_secrets SET created_at = DATETIME('now', '-181 days') WHERE key_type = 'ca_rotation_meta'")
	srv.rotateCAIfNeeded() // Second call should rotate

	// 3. Verify bundle size
	bundle = srv.ca.GetUserCAPublicBundle()
	if len(bundle) != 2 {
		t.Errorf("expected 2 CA keys after rotation, got %d", len(bundle))
	}

	// 4. Verify second key is the .bak one
	// (Implementation proof: RotateCAKeys moves user_ca to user_ca.bak and creates new user_ca)
	if _, err := os.Stat(filepath.Join(tmpDir, "user_ca.bak")); err != nil {
		t.Errorf("user_ca.bak missing after rotation")
	}
}
