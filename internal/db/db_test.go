package db_test

import (
	"testing"

	"github.com/SecareLupus/Fenrir_Homelab_SSH_CA/internal/db"
	_ "modernc.org/sqlite"
)

func newTestDB(t *testing.T) *db.DB {
	// Use in-memory DB for tests
	d, err := db.Init(":memory:", "", "test-encryption-key")
	if err != nil {
		t.Fatalf("failed to init db: %v", err)
	}
	return d
}

func TestUserLifecycle(t *testing.T) {
	d := newTestDB(t)
	defer d.Close()

	// 1. Create User
	err := d.CreateUser("testuser", "hashedpass")
	if err != nil {
		t.Fatalf("failed to create user: %v", err)
	}

	// 2. Verify User Exists
	hash, err := d.GetUserHash("testuser")
	if err != nil {
		t.Fatalf("failed to get user hash: %v", err)
	}
	if hash != "hashedpass" {
		t.Errorf("expected hash 'hashedpass', got '%s'", hash)
	}

	// 3. User ID lookup
	id, err := d.GetUserID("testuser")
	if err != nil || id == 0 {
		t.Errorf("failed to get user ID: %v", err)
	}

	// 4. Update Enabled Status
	err = d.SetUserEnabled("testuser", false)
	if err != nil {
		t.Errorf("failed to disable user: %v", err)
	}
	if d.IsUserEnabled("testuser") {
		t.Error("user should be disabled")
	}
}

func TestPublicKeys(t *testing.T) {
	d := newTestDB(t)
	defer d.Close()

	d.CreateUser("testuser", "pass")
	uid, _ := d.GetUserID("testuser")

	fp := "SHA256:testfingerprint"
	content := "ssh-ed25519 AAAAcontent"

	// 1. Register Key
	err := d.RegisterPublicKey(uid, fp, "ssh-ed25519", content, "test key")
	if err != nil {
		t.Fatalf("failed to register key: %v", err)
	}

	// 2. Check Ownership
	owner, err := d.CheckPublicKeyOwnership(fp)
	if err != nil {
		t.Fatalf("failed to check ownership: %v", err)
	}
	if owner != "testuser" {
		t.Errorf("expected owner 'testuser', got '%s'", owner)
	}

	// 3. Revoke Key
	err = d.RevokeKeyByFingerprint(fp, "compromised")
	if err != nil {
		t.Fatalf("failed to revoke key: %v", err)
	}

	// 4. Check Revocation List
	revoked, err := d.ListRevokedPublicKeys()
	if err != nil {
		t.Fatalf("failed to list revoked: %v", err)
	}
	if len(revoked) == 0 {
		t.Error("expected revoked key in list")
	}
}

func TestGroupsAndTTL(t *testing.T) {
	d := newTestDB(t)
	defer d.Close()

	d.CreateUser("user1", "pass")
	d.CreateGroup("admins", "Administrator Group")
	d.CreateGroup("devs", "Developers")

	// Setup TTLs
	// User limit: 1 hour
	// Devs limit: 8 hours
	// Admins limit: 24 hours
	d.SetUserMaxTTL("user1", 3600)
	d.SetGroupMaxTTL("devs", 8*3600)
	d.SetGroupMaxTTL("admins", 24*3600)

	// 1. Check User TTL (no groups)
	ttl, _ := d.GetMaxTTL("user1")
	if ttl != 3600 {
		t.Errorf("expected 3600, got %d", ttl)
	}

	// 2. Add to Devs
	d.AddUserToGroup("user1", "devs")
	ttl, _ = d.GetMaxTTL("user1")
	if ttl != 8*3600 {
		t.Errorf("expected 28800 (8h), got %d", ttl)
	}

	// 3. Add to Admins (should take precedence)
	d.AddUserToGroup("user1", "admins")
	ttl, _ = d.GetMaxTTL("user1")
	if ttl != 24*3600 {
		t.Errorf("expected 86400 (24h), got %d", ttl)
	}
}

func TestHosts(t *testing.T) {
	d := newTestDB(t)
	defer d.Close()

	hostname := "server.local"
	fp := "SHA256:hostfingerprint"

	// 1. Register Host
	err := d.RegisterHost(hostname, fp)
	if err != nil {
		t.Fatalf("failed to register host: %v", err)
	}

	// 2. Lookup by API Key (initially none)
	_, err = d.GetHostByAPIKey("somehash")
	if err == nil {
		t.Error("expected error for unknown api key")
	}

	// 3. Set API Key
	d.SetHostAPIKey(hostname, "validhash")
	host, err := d.GetHostByAPIKey("validhash")
	if err != nil {
		t.Fatalf("failed to lookup host by key: %v", err)
	}
	if host != hostname {
		t.Errorf("expected hostname %s, got %s", hostname, host)
	}
}
