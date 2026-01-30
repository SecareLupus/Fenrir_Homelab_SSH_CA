package ca

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/SecareLupus/Fenrir_Homelab_SSH_CA/internal/config"
)

func TestCARotationSafetyAndRecovery(t *testing.T) {
	tmpDir, err := os.MkdirTemp("", "ca-test-*")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(tmpDir)

	cfg := &config.Config{
		KeyPath:      tmpDir,
		CAPassphrase: "test-passphrase",
	}

	// 1. Initial Setup
	s, err := New(cfg)
	if err != nil {
		t.Fatalf("Initial setup failed: %v", err)
	}
	if len(s.userSigners) != 1 || len(s.hostSigners) != 1 {
		t.Errorf("Expected 1 signer each, got user=%d, host=%d", len(s.userSigners), len(s.hostSigners))
	}

	userPath := filepath.Join(tmpDir, "user_ca")
	hostPath := filepath.Join(tmpDir, "host_ca")
	userBak := userPath + ".bak"
	// hostBak := hostPath + ".bak"

	// 2. Simulate Partial Rotation Failure (user_ca moved to .bak, host_ca still active)
	if err := os.Rename(userPath, userBak); err != nil {
		t.Fatal(err)
	}
	if fileExists(userPath) {
		t.Fatal("user_ca should be missing")
	}

	// 3. Restart Service and Verify Auto-Recovery
	s2, err := New(cfg)
	if err != nil {
		t.Fatalf("Service restart failed: %v", err)
	}

	if !fileExists(userPath) {
		t.Errorf("user_ca should have been restored from .bak")
	}
	if len(s2.userSigners) != 1 || len(s2.hostSigners) != 1 {
		t.Errorf("After recovery: expected 1 signer each, got user=%d, host=%d", len(s2.userSigners), len(s2.hostSigners))
	}

	// 4. Test Successful Full Rotation
	if err := s2.RotateCAKeys(cfg); err != nil {
		t.Fatalf("Rotation failed: %v", err)
	}

	if !fileExists(userPath) || !fileExists(hostPath) || !fileExists(userBak) || !fileExists(userBak) {
		t.Errorf("After rotation: files missing")
	}

	// Should have 2 signers each (active + backup)
	if len(s2.userSigners) != 2 || len(s2.hostSigners) != 2 {
		t.Errorf("After rotation: expected 2 signers each, got user=%d, host=%d", len(s2.userSigners), len(s2.hostSigners))
	}
}
