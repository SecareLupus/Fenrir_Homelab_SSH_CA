package ca_test

import (
	"crypto/ed25519"
	"crypto/rand"
	"testing"

	"github.com/SecareLupus/Fenrir_Homelab_SSH_CA/internal/ca"
	"github.com/SecareLupus/Fenrir_Homelab_SSH_CA/internal/config"
	"golang.org/x/crypto/ssh"
)

func newTestCA(t *testing.T) *ca.Service {
	tmpDir := t.TempDir()
	cfg := &config.Config{
		KeyPath:      tmpDir,
		CAPassphrase: "test-passphrase",
	}

	service, err := ca.New(cfg)
	if err != nil {
		t.Fatalf("failed to create CA: %v", err)
	}
	return service
}

func generateUserKey(t *testing.T) ssh.PublicKey {
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("failed to gen key: %v", err)
	}
	sshPub, err := ssh.NewPublicKey(priv.Public())
	if err != nil {
		t.Fatalf("failed to make ssh pub: %v", err)
	}
	return sshPub
}

func TestInitialization(t *testing.T) {
	tmpDir := t.TempDir()
	cfg := &config.Config{
		KeyPath:      tmpDir,
		CAPassphrase: "secure",
	}

	// 1. First Run (Generate Keys)
	s1, err := ca.New(cfg)
	if err != nil {
		t.Fatalf("first run failed: %v", err)
	}
	if s1.GetUserCAPublicKey() == nil {
		t.Error("user ca key missing")
	}
	if s1.GetHostCAPublicKey() == nil {
		t.Error("host ca key missing")
	}

	// 2. Second Run (Load Keys)
	s2, err := ca.New(cfg)
	if err != nil {
		t.Fatalf("second run failed: %v", err)
	}

	// Keys should be identical
	k1 := ssh.MarshalAuthorizedKey(s1.GetUserCAPublicKey())
	k2 := ssh.MarshalAuthorizedKey(s2.GetUserCAPublicKey())
	if string(k1) != string(k2) {
		t.Error("loaded key differs from generated key")
	}
}

func TestSignUserCertificate(t *testing.T) {
	s := newTestCA(t)
	userPub := generateUserKey(t)
	principals := []string{"testuser", "group1"}
	ttl := uint64(3600)

	cert, err := s.SignUserCertificate(userPub, "key-id", principals, ttl)
	if err != nil {
		t.Fatalf("signing failed: %v", err)
	}

	// Validation
	if cert.CertType != ssh.UserCert {
		t.Errorf("expected UserCert type, got %d", cert.CertType)
	}
	if len(cert.ValidPrincipals) != 2 {
		t.Errorf("expected 2 principals, got %d", len(cert.ValidPrincipals))
	}

	// Verify signature using the CA's public key
	caPub := s.GetUserCAPublicKey()
	checker := &ssh.CertChecker{
		IsUserAuthority: func(auth ssh.PublicKey) bool {
			return string(ssh.MarshalAuthorizedKey(auth)) == string(ssh.MarshalAuthorizedKey(caPub))
		},
	}

	if err := checker.CheckCert("testuser", cert); err != nil {
		t.Errorf("cert verification failed: %v", err)
	}
}

func TestSignHostCertificate(t *testing.T) {
	s := newTestCA(t)
	hostPub := generateUserKey(t)
	principals := []string{"myserver.local"}
	ttl := uint64(86400)

	cert, err := s.SignHostCertificate(hostPub, "host-id", principals, ttl)
	if err != nil {
		t.Fatalf("signing failed: %v", err)
	}

	if cert.CertType != ssh.HostCert {
		t.Errorf("expected HostCert type, got %d", cert.CertType)
	}

	// Host certs should NOT have extensions like 'permit-pty' usually,
	// checking logic in ca.go
	if len(cert.Extensions) != 0 {
		t.Errorf("expected no extensions for host cert, got %v", cert.Extensions)
	}
}
