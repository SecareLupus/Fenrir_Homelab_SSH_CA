package web

import (
	"crypto/ed25519"
	"crypto/rand"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"
)

func TestApprovalWorkflow(t *testing.T) {
	s := setupServer(t)
	d := s.db
	// 1. Setup: Create "sensitive" group
	d.CreateGroup("sensitive", "High risk group")
	d.Exec("UPDATE groups SET sudo_enabled = 1 WHERE name = 'sensitive'")
	d.SetGroupApprovalRequired("sensitive", true)

	// 2. Setup: Create user "alice" and "admin"
	d.CreateUser("alice", "password")
	d.CreateUser("admin", "adminpass")
	d.Exec("UPDATE users SET role = 'admin' WHERE username = 'admin'")

	// Add Alice to sensitive group
	var uid, gid int
	d.QueryRow("SELECT id FROM users WHERE username = 'alice'").Scan(&uid)
	d.QueryRow("SELECT id FROM groups WHERE name = 'sensitive'").Scan(&gid)
	d.Exec("INSERT INTO user_groups (user_id, group_id) VALUES (?, ?)", uid, gid)

	// Generate key for Alice
	_, priv, _ := ed25519.GenerateKey(rand.Reader)
	pub, _ := ssh.NewPublicKey(priv.Public())
	pubBytes := ssh.MarshalAuthorizedKey(pub)

	// 3. Alice requests "sensitive" principal
	form := url.Values{}
	form.Add("fingerprint", ssh.FingerprintSHA256(pub))
	form.Add("type", "ssh-ed25519")
	form.Add("pubkey", string(pubBytes))
	// server.go: pubKeyStr := r.PostFormValue("key") || r.FormValue("public_key")
	// Let's check server.go
	// It reads pubKey from body/form?
	// Step 1257 showed: pubKeyStr := ...? No, it showed logic AFTER parsing.
	// "3. Register Key if new"
	// Usually it reads from body or form.
	// Assuming "key" field.

	// Wait, earlier I saw: `pubKey, _, _, _, err := ssh.ParseAuthorizedKey([]byte(req.PublicKey))` in Approval Handler.
	// But `handleCertRequest`?
	// It calls `s.db.RegisterPublicKey`.
	// Let's assume "key" is correct form value.

	form.Add("principals", "alice,sensitive")

	req := httptest.NewRequest("POST", "/cert/request", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	cookie, _ := s.signJSON(sessionData{Username: "alice", Expires: time.Now().Add(1 * time.Hour).Unix()})
	req.AddCookie(&http.Cookie{Name: "session_user", Value: cookie})

	w := httptest.NewRecorder()
	s.handleCertRequest(w, req)

	if w.Code != http.StatusAccepted {
		t.Fatalf("expected 202 Accepted, got %d. Body: %s", w.Code, w.Body.String())
	}
	// Parse ID
	bodyStub := "Request Pending Approval. ID: "
	if !strings.Contains(w.Body.String(), bodyStub) {
		t.Fatalf("unexpected body: %s", w.Body.String())
	}
	idStr := strings.TrimSpace(strings.TrimPrefix(w.Body.String(), bodyStub))

	// 4. Verify DB state
	pending, err := d.ListPendingCertRequests()
	if err != nil {
		t.Fatalf("failed to list pending: %v", err)
	}
	if len(pending) != 1 {
		t.Errorf("expected 1 pending request, got %d", len(pending))
	}
	if pending[0].Username != "alice" {
		t.Errorf("expected username alice, got %s", pending[0].Username)
	}

	// 5. Admin Approves
	formApprove := url.Values{}
	formApprove.Add("id", idStr)
	formApprove.Add("action", "approve")

	reqApprove := httptest.NewRequest("POST", "/admin/approvals/process", strings.NewReader(formApprove.Encode()))
	reqApprove.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	adminCookie, _ := s.signJSON(sessionData{Username: "admin", Expires: time.Now().Add(1 * time.Hour).Unix()})
	reqApprove.AddCookie(&http.Cookie{Name: "session_user", Value: adminCookie})

	wApprove := httptest.NewRecorder()
	s.handleAdminApprove(wApprove, reqApprove)

	if wApprove.Code != http.StatusSeeOther {
		t.Fatalf("expected redirect after approval, got %d. Body: %s", wApprove.Code, wApprove.Body.String())
	}

	// 6. Verify Request is Approved and has Cert
	dbReq, err := d.GetCertRequest(pending[0].ID)
	if err != nil {
		t.Fatalf("failed to get req: %v", err)
	}
	if dbReq.Status != "APPROVED" {
		t.Errorf("expected status APPROVED, got %s", dbReq.Status)
	}
	if dbReq.SignedCertificate == "" {
		t.Error("signed certificate is empty")
	}

	// 7. Alice Picks Up
	reqPickup := httptest.NewRequest("GET", "/cert/pickup?id="+idStr, nil)
	reqPickup.AddCookie(&http.Cookie{Name: "session_user", Value: cookie})
	wPickup := httptest.NewRecorder()
	s.handleCertPickup(wPickup, reqPickup)

	if wPickup.Code != 200 {
		t.Fatalf("expected 200 OK pickup, got %d", wPickup.Code)
	}
	certContent := wPickup.Body.String()
	if !strings.Contains(certContent, "ssh-ed25519-cert-v01@openssh.com") {
		t.Error("pickup response does not look like a cert")
	}
}
