package web

import (
	"fmt"
	"net/http"
	"strconv"
	"strings"

	"golang.org/x/crypto/ssh"
)

func (s *Server) handleAdminApprovals(w http.ResponseWriter, r *http.Request) {
	username := s.authenticate(r)
	if !s.isAdmin(username) {
		http.Error(w, "Forbidden", 403)
		return
	}

	requests, err := s.db.ListPendingCertRequests()
	if err != nil {
		http.Error(w, "Failed to list requests: "+err.Error(), 500)
		return
	}

	data := map[string]any{
		"User":     username,
		"IsAdmin":  true,
		"Requests": requests,
	}
	s.render(w, "admin_approvals.html", data)
}

func (s *Server) handleAdminApprove(w http.ResponseWriter, r *http.Request) {
	username := s.authenticate(r)
	if !s.isAdmin(username) {
		http.Error(w, "Forbidden", 403)
		return
	}

	if r.Method != "POST" {
		http.Error(w, "Method not allowed", 405)
		return
	}

	idStr := r.FormValue("id")
	id, _ := strconv.Atoi(idStr)
	action := r.FormValue("action") // "approve" or "reject"

	req, err := s.db.GetCertRequest(id)
	if err != nil {
		http.Error(w, "Request not found", 404)
		return
	}

	if req.Status != "PENDING" {
		http.Error(w, "Request already processed", 400)
		return
	}

	if action == "reject" {
		s.db.RejectCertRequest(id, username)
		s.db.LogEvent(nil, "cert_request_rejected", fmt.Sprintf("id=%d by=%s", id, username))
		http.Redirect(w, r, "/admin/approvals", http.StatusSeeOther)
		return
	}

	if action == "approve" {
		// Sign the cert!
		// Parse the public key
		pubKey, _, _, _, err := ssh.ParseAuthorizedKey([]byte(req.PublicKey))
		if err != nil {
			http.Error(w, "Invalid public key in request", 500)
			return
		}

		// Re-validate principals
		var principals []string
		if req.ValidPrincipals != "" {
			principals = strings.Split(req.ValidPrincipals, ",")
		}
		if len(principals) == 0 {
			principals = []string{req.Username}
		}

		// Sign
		ttl := uint64(43200) // 12 hours default for approved certs
		cert, err := s.ca.SignUserCertificate(pubKey, req.Username, principals, ttl)
		if err != nil {
			http.Error(w, "Signing failed: "+err.Error(), 500)
			return
		}

		certBytes := ssh.MarshalAuthorizedKey(cert)
		s.db.ApproveCertRequest(id, username, string(certBytes))

		// Log
		uid, _ := s.db.GetUserID(req.Username)
		s.db.LogEvent(&uid, "cert_approved", fmt.Sprintf("id=%d", id))
		s.db.StoreCertificate(cert.Serial, ssh.FingerprintSHA256(pubKey), "user", strings.Join(principals, ","), int64(cert.ValidAfter), int64(cert.ValidBefore))

		http.Redirect(w, r, "/admin/approvals", http.StatusSeeOther)
		return
	}

	http.Error(w, "Invalid action", 400)
}

func (s *Server) handleCertPickup(w http.ResponseWriter, r *http.Request) {
	idStr := r.URL.Query().Get("id")
	id, _ := strconv.Atoi(idStr)

	req, err := s.db.GetCertRequest(id)
	if err != nil {
		http.Error(w, "Request not found", 404)
		return
	}

	// Ideally, check if the authenticated user matches the requester!
	// But /cert/pickup might be accessed by CLI tools potentially using standard auth?
	// For now, let's enforce auth.
	username := s.authenticate(r)
	if username != req.Username && !s.isAdmin(username) {
		http.Error(w, "Forbidden", 403)
		return
	}

	if req.Status == "PENDING" {
		w.WriteHeader(http.StatusAccepted) // 202
		fmt.Fprintf(w, "Request pending approval")
		return
	}

	if req.Status == "REJECTED" {
		w.WriteHeader(http.StatusForbidden) // 403
		fmt.Fprintf(w, "Request rejected")
		return
	}

	if req.Status == "APPROVED" {
		if req.SignedCertificate == "" {
			http.Error(w, "Certificate missing (internal error)", 500)
			return
		}
		w.Header().Set("Content-Type", "text/plain")
		w.Write([]byte(req.SignedCertificate))
		return
	}

	http.Error(w, "Unknown status", 500)
}
