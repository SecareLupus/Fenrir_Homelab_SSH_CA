package db

import (
	"time"
)

// CertRequest represents a request for certificate issuance requiring approval
type CertRequest struct {
	ID                int
	Username          string
	PublicKey         string
	ValidPrincipals   string
	Reason            string
	Status            string
	Approver          string
	SignedCertificate string
	CreatedAt         time.Time
	UpdatedAt         time.Time
}

// CreateCertRequest creates a new certificate request
func (d *DB) CreateCertRequest(username, pubKey, principals, reason string) (int, error) {
	res, err := d.Exec("INSERT INTO cert_requests (username, pubkey, valid_principals, reason, updated_at) VALUES (?, ?, ?, ?, CURRENT_TIMESTAMP)", username, pubKey, principals, reason)
	if err != nil {
		return 0, err
	}
	id, err := res.LastInsertId()
	return int(id), err
}

// ListPendingCertRequests returns all requests with status PENDING
func (d *DB) ListPendingCertRequests() ([]CertRequest, error) {
	rows, err := d.Query("SELECT id, username, pubkey, valid_principals, reason, status, created_at FROM cert_requests WHERE status = 'PENDING' ORDER BY created_at ASC")
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var requests []CertRequest
	for rows.Next() {
		var req CertRequest
		var createdAt string
		if err := rows.Scan(&req.ID, &req.Username, &req.PublicKey, &req.ValidPrincipals, &req.Reason, &req.Status, &createdAt); err != nil {
			return nil, err
		}
		req.CreatedAt, _ = time.Parse("2006-01-02 15:04:05", createdAt)
		requests = append(requests, req)
	}
	return requests, nil
}

// GetCertRequest retrieves a specific request
func (d *DB) GetCertRequest(id int) (*CertRequest, error) {
	var req CertRequest
	var createdAt string
	var updatedAt string
	err := d.QueryRow("SELECT id, username, pubkey, valid_principals, reason, status, COALESCE(approver, ''), COALESCE(signed_certificate, ''), created_at, COALESCE(updated_at, created_at) FROM cert_requests WHERE id = ?", id).
		Scan(&req.ID, &req.Username, &req.PublicKey, &req.ValidPrincipals, &req.Reason, &req.Status, &req.Approver, &req.SignedCertificate, &createdAt, &updatedAt)
	if err != nil {
		return nil, err
	}
	req.CreatedAt, _ = time.Parse("2006-01-02 15:04:05", createdAt)
	req.UpdatedAt, _ = time.Parse("2006-01-02 15:04:05", updatedAt)
	return &req, nil
}

// ApproveCertRequest marks a request as approved and saves the cert
func (d *DB) ApproveCertRequest(id int, approver, cert string) error {
	_, err := d.Exec("UPDATE cert_requests SET status = 'APPROVED', approver = ?, signed_certificate = ?, updated_at = CURRENT_TIMESTAMP WHERE id = ?", approver, cert, id)
	return err
}

// RejectCertRequest marks a request as rejected
func (d *DB) RejectCertRequest(id int, approver string) error {
	_, err := d.Exec("UPDATE cert_requests SET status = 'REJECTED', approver = ?, updated_at = CURRENT_TIMESTAMP WHERE id = ?", approver, id)
	return err
}

// GetGroupApprovalRequired checks if a group requires approval
func (d *DB) GetGroupApprovalRequired(groupName string) (bool, error) {
	var required int
	err := d.QueryRow("SELECT requires_approval FROM groups WHERE name = ?", groupName).Scan(&required)
	if err != nil {
		return false, err
	}
	return required == 1, nil
}

// SetGroupApprovalRequired updates the approval flag for a group
func (d *DB) SetGroupApprovalRequired(name string, required bool) error {
	val := 0
	if required {
		val = 1
	}
	_, err := d.Exec("UPDATE groups SET requires_approval = ? WHERE name = ?", val, name)
	return err
}
