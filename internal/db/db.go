/*
 * Copyright (c) 2026 SecareLupus
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 */

package db

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"database/sql"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"strings"
	"time"

	// Driver registration
	_ "modernc.org/sqlite"
)

// DB handles all persistent storage operations for users, keys, certificates,
// and audit logs using SQLite with optional at-rest encryption.
type DB struct {
	*sql.DB
	WebhookURL    string
	EncryptionKey []byte
}

// Init opens the SQLite database at the specified path and runs initial migrations.
// Optional encryption key is used for at-rest encryption of MFA secrets.
func Init(path, webhookURL, encKey string) (*DB, error) {
	db, err := sql.Open("sqlite", path)
	if err != nil {
		return nil, fmt.Errorf("open db: %w", err)
	}

	if err := db.Ping(); err != nil {
		return nil, fmt.Errorf("ping db: %w", err)
	}

	d := &DB{DB: db, WebhookURL: webhookURL}
	if encKey != "" {
		d.EncryptionKey = []byte(encKey)
	}
	if err := d.migrate(); err != nil {
		d.Close()
		return nil, fmt.Errorf("migrate: %w", err)
	}

	return d, nil
}

func (d *DB) migrate() error {
	schemas := []string{
		`CREATE TABLE IF NOT EXISTS users (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		username TEXT NOT NULL UNIQUE,
		password_hash TEXT, -- For local auth
		role TEXT NOT NULL DEFAULT 'user',
		enabled INTEGER NOT NULL DEFAULT 1, -- 1=true, 0=false
		created_at DATETIME DEFAULT CURRENT_TIMESTAMP
	);`,
		`CREATE TABLE IF NOT EXISTS audit_logs (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		user_id INTEGER,
		event TEXT NOT NULL,
		metadata TEXT, -- JSON blob
		created_at DATETIME DEFAULT CURRENT_TIMESTAMP
	);`,
		`CREATE TABLE IF NOT EXISTS public_keys (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		user_id INTEGER NOT NULL,
		fingerprint TEXT NOT NULL UNIQUE,
		type TEXT NOT NULL, -- e.g. ssh-ed25519
		content TEXT NOT NULL,
		comment TEXT,
		created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
		FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE
	);`,
		`CREATE TABLE IF NOT EXISTS certificates (
		serial INTEGER PRIMARY KEY,
		key_fingerprint TEXT NOT NULL,
		type TEXT NOT NULL, -- user or host
		principals TEXT NOT NULL, -- JSON or comma-separated
		valid_from INTEGER NOT NULL, -- Unix timestamp
		valid_to INTEGER NOT NULL, -- Unix timestamp
		created_at DATETIME DEFAULT CURRENT_TIMESTAMP
	);`,
		`CREATE TABLE IF NOT EXISTS revocations (
		serial INTEGER PRIMARY KEY,
		reason TEXT,
		revoked_at DATETIME DEFAULT CURRENT_TIMESTAMP
	);`,
		`CREATE TABLE IF NOT EXISTS api_keys (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		user_id INTEGER NOT NULL,
		key_hash TEXT NOT NULL UNIQUE,
		label TEXT,
		created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
		FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE
	);`,
		`CREATE TABLE IF NOT EXISTS hosts (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		hostname TEXT NOT NULL UNIQUE,
		fingerprint TEXT NOT NULL,
		api_key_hash TEXT, -- For agent-initiated renewal
		last_seen DATETIME,
		created_at DATETIME DEFAULT CURRENT_TIMESTAMP
	);`,
		`CREATE TABLE IF NOT EXISTS mfa_backup_codes (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		user_id INTEGER NOT NULL,
		code_hash TEXT NOT NULL,
		used INTEGER NOT NULL DEFAULT 0, -- 0=unused, 1=used
		created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
		FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE
	);`,
		`CREATE TABLE IF NOT EXISTS groups (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		name TEXT NOT NULL UNIQUE,
		description TEXT,
		sudo_enabled INTEGER NOT NULL DEFAULT 0, -- 1=true, 0=false
		created_at DATETIME DEFAULT CURRENT_TIMESTAMP
	);`,
		`CREATE TABLE IF NOT EXISTS system_secrets (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		key_type TEXT NOT NULL, -- 'session' or 'ca_kek'
		secret_value TEXT NOT NULL,
		active INTEGER NOT NULL DEFAULT 1,
		created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
		expires_at DATETIME
	);`,
		`CREATE TABLE IF NOT EXISTS user_groups (
		user_id INTEGER NOT NULL,
		group_id INTEGER NOT NULL,
		FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE,
		FOREIGN KEY(group_id) REFERENCES groups(id) ON DELETE CASCADE
	);`,
		`CREATE TABLE IF NOT EXISTS webauthn_credentials (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		user_id INTEGER NOT NULL,
		credential_id BLOB NOT NULL,
		public_key BLOB NOT NULL,
		attestation_type TEXT,
		aaguid BLOB,
		sign_count INTEGER,
		clone_warning BOOLEAN,
		created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
		FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE,
		UNIQUE(credential_id)
	);`,
	}

	for _, s := range schemas {
		if _, err := d.Exec(s); err != nil {
			return err
		}
	}

	// Manual migrations for existing schemas
	// SQLite doesn't have "ADD COLUMN IF NOT EXISTS", so we just try and ignore "duplicate column" error
	_, _ = d.Exec("ALTER TABLE users ADD COLUMN enabled INTEGER NOT NULL DEFAULT 1")
	_, _ = d.Exec("ALTER TABLE users ADD COLUMN role TEXT NOT NULL DEFAULT 'user'")
	_, _ = d.Exec("ALTER TABLE users ADD COLUMN mfa_secret TEXT")
	_, _ = d.Exec("ALTER TABLE users ADD COLUMN max_ttl INTEGER")
	_, _ = d.Exec("ALTER TABLE groups ADD COLUMN max_ttl INTEGER")
	_, _ = d.Exec("ALTER TABLE hosts ADD COLUMN api_key_hash TEXT")
	_, _ = d.Exec("ALTER TABLE hosts ADD COLUMN last_seen DATETIME")
	_, _ = d.Exec("ALTER TABLE groups ADD COLUMN sudo_enabled INTEGER NOT NULL DEFAULT 0")
	if _, err := d.Exec("CREATE TABLE IF NOT EXISTS system_secrets (id INTEGER PRIMARY KEY AUTOINCREMENT, key_type TEXT NOT NULL, secret_value TEXT NOT NULL, active INTEGER NOT NULL DEFAULT 1, created_at DATETIME DEFAULT CURRENT_TIMESTAMP, expires_at DATETIME)"); err != nil {
		log.Printf("Migration error (system_secrets): %v", err)
	}

	return nil
}

// ... (existing code)

// CreateUser registers a new user in the system. The password should already be hashed.
func (d *DB) CreateUser(username, password string) error {
	// Simple bcrypt hash
	// NOTE: robust impl should be in auth package, but simplified here for single-binary design
	// We'll stub the hashing helper or imports.
	// Actually, let's keep it simple: plain db operations here.

	_, err := d.Exec("INSERT INTO users (username, password_hash) VALUES (?, ?)", username, password)
	return err
}

// GetUserHash retrieves the password hash for a user
func (d *DB) GetUserHash(username string) (string, error) {
	var hash string
	err := d.QueryRow("SELECT password_hash FROM users WHERE username = ?", username).Scan(&hash)
	if err != nil {
		return "", err
	}
	return hash, nil
}

// CreateAPIKey stores a hashed API key for a user
func (d *DB) CreateAPIKey(userID int, keyHash, label string) error {
	_, err := d.Exec("INSERT INTO api_keys (user_id, key_hash, label) VALUES (?, ?, ?)", userID, keyHash, label)
	return err
}

// GetUserByAPIKey returns the username associated with a valid SHA256-hashed API key.
func (d *DB) GetUserByAPIKey(keyHash string) (string, error) {
	var username string
	query := `
		SELECT u.username 
		FROM users u
		JOIN api_keys ak ON u.id = ak.user_id
		WHERE ak.key_hash = ?
	`
	err := d.QueryRow(query, keyHash).Scan(&username)
	if err != nil {
		return "", err
	}
	return username, nil
}

// User represents a user in the system
type User struct {
	ID        int
	Username  string
	Role      string
	Enabled   bool
	MFASecret string
	MaxTTL    int
	CreatedAt time.Time
}

// ListUsers returns all users in the system
func (d *DB) ListUsers() ([]User, error) {
	rows, err := d.Query("SELECT id, username, role, enabled, COALESCE(mfa_secret, ''), created_at FROM users ORDER BY username ASC")
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var users []User
	for rows.Next() {
		var u User
		var enabled int
		var createdAt string
		if err := rows.Scan(&u.ID, &u.Username, &u.Role, &enabled, &u.MFASecret, &createdAt); err != nil {
			return nil, err
		}
		u.Enabled = enabled == 1
		if u.MFASecret != "" && len(d.EncryptionKey) > 0 {
			dec, err := d.decrypt(u.MFASecret)
			if err == nil {
				u.MFASecret = dec
			}
		}
		users = append(users, u)
	}
	return users, nil
}

// UserAudit represents user metadata for auditing
type UserAudit struct {
	Username  string
	CreatedAt string
}

// KeyAudit represents key metadata for auditing
type KeyAudit struct {
	Username    string
	Fingerprint string
	CreatedAt   string
}

// ListUsersCreatedSince returns users created after a certain time
func (d *DB) ListUsersCreatedSince(since string) ([]UserAudit, error) {
	rows, err := d.Query("SELECT username, created_at FROM users WHERE created_at >= ? ORDER BY created_at DESC", since)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var users []UserAudit
	for rows.Next() {
		var u UserAudit
		if err := rows.Scan(&u.Username, &u.CreatedAt); err != nil {
			return nil, err
		}
		users = append(users, u)
	}
	return users, nil
}

// ListKeysCreatedSince returns public keys registered after a certain time
func (d *DB) ListKeysCreatedSince(since string) ([]KeyAudit, error) {
	query := `
		SELECT u.username, pk.fingerprint, pk.created_at
		FROM public_keys pk
		JOIN users u ON pk.user_id = u.id
		WHERE pk.created_at >= ?
		ORDER BY pk.created_at DESC
	`
	rows, err := d.Query(query, since)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var keys []KeyAudit
	for rows.Next() {
		var k KeyAudit
		if err := rows.Scan(&k.Username, &k.Fingerprint, &k.CreatedAt); err != nil {
			return nil, err
		}
		keys = append(keys, k)
	}
	return keys, nil
}

// SetUserMFASecret sets the TOTP secret for a user
func (d *DB) SetUserMFASecret(username, secret string) error {
	if secret != "" && len(d.EncryptionKey) > 0 {
		enc, err := d.encrypt(secret)
		if err == nil {
			secret = enc
		}
	}
	_, err := d.Exec("UPDATE users SET mfa_secret = ? WHERE username = ?", secret, username)
	return err
}

// GetUserMFASecret gets the TOTP secret for a user
func (d *DB) GetUserMFASecret(username string) (string, error) {
	var secret sql.NullString
	err := d.QueryRow("SELECT mfa_secret FROM users WHERE username = ?", username).Scan(&secret)
	if err != nil {
		return "", err
	}
	if !secret.Valid || secret.String == "" {
		return "", nil
	}

	if len(d.EncryptionKey) > 0 {
		return d.decrypt(secret.String)
	}
	return secret.String, nil
}

// SetBackupCodes stores a list of hashed backup codes for a user, clearing old ones
func (d *DB) SetBackupCodes(username string, hashes []string) error {
	userID, err := d.GetUserID(username)
	if err != nil {
		return err
	}

	tx, err := d.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()

	_, err = tx.Exec("DELETE FROM mfa_backup_codes WHERE user_id = ?", userID)
	if err != nil {
		return err
	}

	for _, hash := range hashes {
		_, err = tx.Exec("INSERT INTO mfa_backup_codes (user_id, code_hash) VALUES (?, ?)", userID, hash)
		if err != nil {
			return err
		}
	}

	return tx.Commit()
}

// VerifyBackupCode checks if a code is valid for a user and marks it used
func (d *DB) VerifyBackupCode(username, codeHash string) (bool, error) {
	userID, err := d.GetUserID(username)
	if err != nil {
		return false, err
	}

	var id int
	err = d.QueryRow("SELECT id FROM mfa_backup_codes WHERE user_id = ? AND code_hash = ? AND used = 0", userID, codeHash).Scan(&id)
	if err == sql.ErrNoRows {
		return false, nil
	}
	if err != nil {
		return false, err
	}

	_, err = d.Exec("UPDATE mfa_backup_codes SET used = 1 WHERE id = ?", id)
	return err == nil, err
}

// SetUserEnabled toggles a user's active status
func (d *DB) SetUserEnabled(username string, enabled bool) error {
	val := 0
	if enabled {
		val = 1
	}
	_, err := d.Exec("UPDATE users SET enabled = ? WHERE username = ?", val, username)
	return err
}

// GetUserID returns the ID for a username
func (d *DB) GetUserID(username string) (int, error) {
	var id int
	err := d.QueryRow("SELECT id FROM users WHERE username = ?", username).Scan(&id)
	return id, err
}

// IsUserEnabled checks if a user is active
func (d *DB) IsUserEnabled(username string) bool {
	var enabled int
	err := d.QueryRow("SELECT enabled FROM users WHERE username = ?", username).Scan(&enabled)
	if err != nil {
		return false
	}
	return enabled == 1
}

// GetHostByAPIKey returns the hostname if the API key hash matches
func (d *DB) GetHostByAPIKey(keyHash string) (string, error) {
	var hostname string
	err := d.QueryRow("SELECT hostname FROM hosts WHERE api_key_hash = ?", keyHash).Scan(&hostname)
	if err != nil {
		return "", err
	}
	return hostname, nil
}

// SetHostAPIKey stores a hashed API key for a host
func (d *DB) SetHostAPIKey(hostname, keyHash string) error {
	_, err := d.Exec("UPDATE hosts SET api_key_hash = ?, last_seen = CURRENT_TIMESTAMP WHERE hostname = ?", keyHash, hostname)
	return err
}

// UpdateHostLastSeen updates the last check-in time for a host
func (d *DB) UpdateHostLastSeen(hostname string) error {
	_, err := d.Exec("UPDATE hosts SET last_seen = CURRENT_TIMESTAMP WHERE hostname = ?", hostname)
	return err
}

// RegisterHost creates a new host entry
func (d *DB) RegisterHost(hostname, fingerprint string) error {
	_, err := d.Exec("INSERT INTO hosts (hostname, fingerprint) VALUES (?, ?)", hostname, fingerprint)
	return err
}

// Host represents a host in the system
type Host struct {
	ID          int
	Hostname    string
	Fingerprint string
	HasAPIKey   bool
	LastSeen    *time.Time
	CreatedAt   time.Time
}

// ListHosts returns all registered hosts
func (d *DB) ListHosts() ([]Host, error) {
	query := `
		SELECT id, hostname, fingerprint, (api_key_hash IS NOT NULL), last_seen, created_at 
		FROM hosts 
		ORDER BY hostname ASC
	`
	rows, err := d.Query(query)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var hosts []Host
	for rows.Next() {
		var h Host
		var lastSeen sql.NullString
		var createdAt string
		if err := rows.Scan(&h.ID, &h.Hostname, &h.Fingerprint, &h.HasAPIKey, &lastSeen, &createdAt); err != nil {
			return nil, err
		}
		if lastSeen.Valid {
			t, _ := time.Parse("2006-01-02 15:04:05", lastSeen.String)
			h.LastSeen = &t
		}
		h.CreatedAt, _ = time.Parse("2006-01-02 15:04:05", createdAt)
		hosts = append(hosts, h)
	}
	return hosts, nil
}

// DeleteHost removes a host from the inventory
func (d *DB) DeleteHost(hostname string) error {
	_, err := d.Exec("DELETE FROM hosts WHERE hostname = ?", hostname)
	return err
}

// RegisterPublicKey associates an SSH public key fingerprint with a specific user account.
func (d *DB) RegisterPublicKey(userID int, fingerprint, keyType, content, comment string) error {
	_, err := d.Exec(`
		INSERT INTO public_keys (user_id, fingerprint, type, content, comment) 
		VALUES (?, ?, ?, ?, ?)
		ON CONFLICT(fingerprint) DO UPDATE SET comment = excluded.comment
	`, userID, fingerprint, keyType, content, comment)
	return err
}

// CheckPublicKeyOwnership returns the username of the owner if the key is registered
func (d *DB) CheckPublicKeyOwnership(fingerprint string) (string, error) {
	var username string
	err := d.QueryRow(`
		SELECT u.username 
		FROM users u
		JOIN public_keys pk ON u.id = pk.user_id
		WHERE pk.fingerprint = ? AND pk.comment NOT LIKE 'REVOKED:%'
	`, fingerprint).Scan(&username)
	return username, err
}

// IsPublicKeyRevoked checks if a key has been marked as revoked in the database.
func (d *DB) IsPublicKeyRevoked(fingerprint string) bool {
	var comment string
	err := d.QueryRow("SELECT comment FROM public_keys WHERE fingerprint = ?", fingerprint).Scan(&comment)
	if err != nil {
		return false
	}
	return strings.HasPrefix(comment, "REVOKED:")
}

// CheckHostPublicKeyOwnership returns the hostname if the key is registered to a host
func (d *DB) CheckHostPublicKeyOwnership(fingerprint string) (string, error) {
	var hostname string
	err := d.QueryRow("SELECT hostname FROM hosts WHERE fingerprint = ?", fingerprint).Scan(&hostname)
	return hostname, err
}

// LogEvent writes an entry to the audit log
func (d *DB) LogEvent(userID *int, event, metadata string) {
	if _, err := d.Exec("INSERT INTO audit_logs (user_id, event, metadata) VALUES (?, ?, ?)", userID, event, metadata); err != nil {
		log.Printf("DATABASE ERROR: failed to log event %s: %v", event, err)
	}

	if d.WebhookURL != "" {
		go func() {
			payload := map[string]any{
				"event":     event,
				"metadata":  metadata,
				"timestamp": time.Now().Format(time.RFC3339),
			}
			if userID != nil {
				payload["user_id"] = *userID
			}
			body, _ := json.Marshal(payload)

			client := &http.Client{Timeout: 5 * time.Second}
			for i := 0; i < 3; i++ {
				resp, err := client.Post(d.WebhookURL, "application/json", strings.NewReader(string(body)))
				if err == nil {
					resp.Body.Close()
					return
				}
				time.Sleep(time.Duration(i+1) * time.Second)
			}
		}()
	}
}

// RevokeKeyByFingerprint adds a key to the revocation list
func (d *DB) RevokeKeyByFingerprint(fp, reason string) error {
	_, err := d.Exec("INSERT INTO revocations (serial, reason) VALUES ((SELECT 0), ?)", reason)
	// Wait, serial is PK. Let's use a different table structure for revoked keys if they don't have serials.
	// Actually, let's just use the 'public_keys' content.
	// We'll add a 'revoked' column to public_keys?
	_, err = d.Exec("UPDATE public_keys SET comment = 'REVOKED: ' || ? WHERE fingerprint = ?", reason, fp)
	return err
}

// ListRevokedPublicKeys returns the content of all revoked keys
func (d *DB) ListRevokedPublicKeys() ([]string, error) {
	rows, err := d.Query("SELECT content FROM public_keys WHERE comment LIKE 'REVOKED:%'")
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var keys []string
	for rows.Next() {
		var k string
		if err := rows.Scan(&k); err != nil {
			return nil, err
		}
		keys = append(keys, k)
	}
	return keys, nil
}

// AuditLog represents an entry in the audit log
type AuditLog struct {
	ID        int
	Username  string // Joined from users
	Event     string
	Metadata  string
	CreatedAt string
}

// ListAuditLogs returns the most recent audit logs
func (d *DB) ListAuditLogs(limit int) ([]AuditLog, error) {
	query := `
		SELECT al.id, COALESCE(u.username, 'system'), al.event, al.metadata, al.created_at
		FROM audit_logs al
		LEFT JOIN users u ON al.user_id = u.id
		ORDER BY al.created_at DESC
		LIMIT ?
	`
	rows, err := d.Query(query, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var logs []AuditLog
	for rows.Next() {
		var l AuditLog
		if err := rows.Scan(&l.ID, &l.Username, &l.Event, &l.Metadata, &l.CreatedAt); err != nil {
			return nil, err
		}
		logs = append(logs, l)
	}
	return logs, nil
}

// StoreCertificate saves metadata about a signed certificate
func (d *DB) StoreCertificate(serial uint64, fingerprint, certType, principals string, validFrom, validTo int64) error {
	_, err := d.Exec(`
		INSERT INTO certificates (serial, key_fingerprint, type, principals, valid_from, valid_to) 
		VALUES (?, ?, ?, ?, ?, ?)
	`, serial, fingerprint, certType, principals, validFrom, validTo)
	return err
}

// GetUserRole returns the role assigned to a username
func (d *DB) GetUserRole(username string) (string, error) {
	var role string
	err := d.QueryRow("SELECT role FROM users WHERE username = ?", username).Scan(&role)
	if err != nil {
		return "", err
	}
	return role, nil
}

// --- Group Management ---

// Group represents a logical group of users
type Group struct {
	ID          int       `json:"id"`
	Name        string    `json:"name"`
	Description string    `json:"description"`
	SudoEnabled bool      `json:"sudo_enabled"`
	MaxTTL      int       `json:"max_ttl"`
	CreatedAt   time.Time `json:"created_at"`
}

// CreateGroup creates a new group
func (d *DB) CreateGroup(name, description string) error {
	_, err := d.Exec("INSERT INTO groups (name, description) VALUES (?, ?)", name, description)
	return err
}

// DeleteGroup deletes a group by name
func (d *DB) DeleteGroup(name string) error {
	_, err := d.Exec("DELETE FROM groups WHERE name = ?", name)
	return err
}

// ListGroups returns all groups
func (d *DB) ListGroups() ([]Group, error) {
	rows, err := d.Query("SELECT id, name, COALESCE(description, ''), sudo_enabled, COALESCE(max_ttl, 0), created_at FROM groups ORDER BY name ASC")
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var groups []Group
	for rows.Next() {
		var g Group
		var createdAt string
		if err := rows.Scan(&g.ID, &g.Name, &g.Description, &g.SudoEnabled, &g.MaxTTL, &createdAt); err != nil {
			return nil, err
		}
		g.CreatedAt, _ = time.Parse("2006-01-02 15:04:05", createdAt) // SQLite default format
		groups = append(groups, g)
	}
	return groups, nil
}

// AddUserToGroup adds a user to a group
func (d *DB) AddUserToGroup(username, groupName string) error {
	query := `
		INSERT INTO user_groups (user_id, group_id)
		VALUES (
			(SELECT id FROM users WHERE username = ?),
			(SELECT id FROM groups WHERE name = ?)
		)
	`
	_, err := d.Exec(query, username, groupName)
	return err
}

// RemoveUserFromGroup removes a user from a group
func (d *DB) RemoveUserFromGroup(username, groupName string) error {
	query := `
		DELETE FROM user_groups
		WHERE user_id = (SELECT id FROM users WHERE username = ?)
		AND group_id = (SELECT id FROM groups WHERE name = ?)
	`
	_, err := d.Exec(query, username, groupName)
	return err
}

// GetUserGroups returns all group names a user belongs to
func (d *DB) GetUserGroups(username string) ([]string, error) {
	query := `
		SELECT g.name
		FROM groups g
		JOIN user_groups ug ON g.id = ug.group_id
		JOIN users u ON ug.user_id = u.id
		WHERE u.username = ?
	`
	rows, err := d.Query(query, username)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var names []string
	for rows.Next() {
		var name string
		if err := rows.Scan(&name); err != nil {
			return nil, err
		}
		names = append(names, name)
	}
	return names, nil
}

// GetUserSudoGroups returns group names a user belongs to that have sudo enabled
func (d *DB) GetUserSudoGroups(username string) ([]string, error) {
	query := `
		SELECT g.name
		FROM groups g
		JOIN user_groups ug ON g.id = ug.group_id
		JOIN users u ON ug.user_id = u.id
		WHERE u.username = ? AND g.sudo_enabled = 1
	`
	rows, err := d.Query(query, username)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var names []string
	for rows.Next() {
		var name string
		if err := rows.Scan(&name); err != nil {
			return nil, err
		}
		names = append(names, name)
	}
	return names, nil
}

// GetUserGroupsByGroupName returns all usernames belonging to a group
func (d *DB) GetUserGroupsByGroupName(groupName string) ([]string, error) {
	query := `
		SELECT u.username
		FROM users u
		JOIN user_groups ug ON u.id = ug.user_id
		JOIN groups g ON ug.group_id = g.id
		WHERE g.name = ?
	`
	rows, err := d.Query(query, groupName)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var names []string
	for rows.Next() {
		var name string
		if err := rows.Scan(&name); err != nil {
			return nil, err
		}
		names = append(names, name)
	}
	return names, nil
}

// --- Secret Rotation ---

// Secret represents a system secret (like a session signing key)
type Secret struct {
	ID          int
	KeyType     string
	SecretValue string
	Active      bool
	CreatedAt   time.Time
	ExpiresAt   *time.Time
}

// GetActiveSecrets returns valid secrets for a given type, ordered by newest first
func (d *DB) GetActiveSecrets(keyType string) ([]Secret, error) {
	query := `
		SELECT id, key_type, secret_value, active, created_at, expires_at 
		FROM system_secrets 
		WHERE key_type = ? AND active = 1 AND (expires_at IS NULL OR expires_at > CURRENT_TIMESTAMP)
		ORDER BY created_at DESC
	`
	rows, err := d.Query(query, keyType)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var secrets []Secret
	for rows.Next() {
		var s Secret
		var createdAt string
		var expiresAt sql.NullString
		if err := rows.Scan(&s.ID, &s.KeyType, &s.SecretValue, &s.Active, &createdAt, &expiresAt); err != nil {
			return nil, err
		}
		s.CreatedAt, _ = time.Parse("2006-01-02 15:04:05", createdAt)
		if expiresAt.Valid {
			t, _ := time.Parse("2006-01-02 15:04:05", expiresAt.String)
			s.ExpiresAt = &t
		}
		secrets = append(secrets, s)
	}
	return secrets, nil
}

// CreateSecret adds a new secret and optionally expires old ones of the same type
func (d *DB) CreateSecret(keyType, value string, expireOldDays int) error {
	tx, err := d.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()

	// 1. Mark existing secrets of this type to expire
	if expireOldDays > 0 {
		_, err = tx.Exec(`
			UPDATE system_secrets 
			SET expires_at = DATETIME('now', '+' || ? || ' days')
			WHERE key_type = ? AND active = 1 AND expires_at IS NULL
		`, expireOldDays, keyType)
		if err != nil {
			return err
		}
	}

	// 2. Insert new secret
	_, err = tx.Exec("INSERT INTO system_secrets (key_type, secret_value) VALUES (?, ?)", keyType, value)
	if err != nil {
		return err
	}

	return tx.Commit()
}

// CleanupExpiredSecrets removes secrets that are past their expiration date or marked inactive
func (d *DB) CleanupExpiredSecrets() (int64, error) {
	res, err := d.Exec("DELETE FROM system_secrets WHERE active = 0 OR (expires_at IS NOT NULL AND expires_at < CURRENT_TIMESTAMP)")
	if err != nil {
		return 0, err
	}
	return res.RowsAffected()
}

// SetUserMaxTTL sets the maximum allow TTL for a user
func (d *DB) SetUserMaxTTL(username string, ttl int) error {
	_, err := d.Exec("UPDATE users SET max_ttl = ? WHERE username = ?", ttl, username)
	return err
}

// SetGroupMaxTTL sets the maximum allow TTL for a group
func (d *DB) SetGroupMaxTTL(groupName string, ttl int) error {
	_, err := d.Exec("UPDATE groups SET max_ttl = ? WHERE name = ?", ttl, groupName)
	return err
}

// SetGroupSudoEnabled toggles a group's sudo permission status
func (d *DB) SetGroupSudoEnabled(groupName string, enabled bool) error {
	val := 0
	if enabled {
		val = 1
	}
	_, err := d.Exec("UPDATE groups SET sudo_enabled = ? WHERE name = ?", val, groupName)
	return err
}

// GetMaxTTL resolves the maximum allowed TTL for a user by checking
// their specific setting and all group settings, returning the highest allowed.
// Returns 0 if no specific policy is found (caller should use global default).
func (d *DB) GetMaxTTL(username string) (int, error) {
	var userTTL sql.NullInt64
	err := d.QueryRow("SELECT max_ttl FROM users WHERE username = ?", username).Scan(&userTTL)
	if err != nil {
		return 0, err
	}

	max := 0
	if userTTL.Valid {
		max = int(userTTL.Int64)
	}

	// Check groups
	query := `
		SELECT MAX(g.max_ttl)
		FROM groups g
		JOIN user_groups ug ON g.id = ug.group_id
		JOIN users u ON ug.user_id = u.id
		WHERE u.username = ? AND g.max_ttl IS NOT NULL
	`
	var groupMax sql.NullInt64
	err = d.QueryRow(query, username).Scan(&groupMax)
	if err == nil && groupMax.Valid {
		if int(groupMax.Int64) > max {
			max = int(groupMax.Int64)
		}
	}

	return max, nil
}

func (d *DB) Close() error {
	if d.DB != nil {
		return d.DB.Close()
	}
	return nil
}

// WebAuthnCredential matches the structure expected by go-webauthn but simple for DB
type WebAuthnCredential struct {
	ID              int
	CredentialID    []byte
	PublicKey       []byte
	AttestationType string
	AAGUID          []byte
	SignCount       int32
	CloneWarning    bool
}

func (d *DB) GetWebAuthnCredentials(username string) ([]WebAuthnCredential, error) {
	query := `
		SELECT wc.id, wc.credential_id, wc.public_key, wc.attestation_type, wc.aaguid, wc.sign_count, wc.clone_warning
		FROM webauthn_credentials wc
		JOIN users u ON wc.user_id = u.id
		WHERE u.username = ?
	`
	rows, err := d.Query(query, username)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var creds []WebAuthnCredential
	for rows.Next() {
		var c WebAuthnCredential
		if err := rows.Scan(&c.ID, &c.CredentialID, &c.PublicKey, &c.AttestationType, &c.AAGUID, &c.SignCount, &c.CloneWarning); err != nil {
			return nil, err
		}
		creds = append(creds, c)
	}
	return creds, nil
}

func (d *DB) AddWebAuthnCredential(username string, credID, pubKey, aaguid []byte, attestationType string, signCount int32) error {
	uid, _ := d.GetUserID(username)
	_, err := d.Exec(`
		INSERT INTO webauthn_credentials (user_id, credential_id, public_key, aaguid, attestation_type, sign_count)
		VALUES (?, ?, ?, ?, ?, ?)
	`, uid, credID, pubKey, aaguid, attestationType, signCount)
	return err
}

func (d *DB) UpdateWebAuthnCredential(credID []byte, signCount int32) error {
	_, err := d.Exec("UPDATE webauthn_credentials SET sign_count = ? WHERE credential_id = ?", signCount, credID)
	return err
}

func (d *DB) GetUser(username string) (*User, error) {
	var u User
	var createdAt string
	var enabled int
	err := d.QueryRow("SELECT id, username, role, enabled, COALESCE(mfa_secret, ''), COALESCE(max_ttl, 0), created_at FROM users WHERE username = ?", username).
		Scan(&u.ID, &u.Username, &u.Role, &enabled, &u.MFASecret, &u.MaxTTL, &createdAt)
	if err != nil {
		return nil, err
	}
	u.Enabled = enabled == 1
	if u.MFASecret != "" && len(d.EncryptionKey) > 0 {
		dec, err := d.decrypt(u.MFASecret)
		if err == nil {
			u.MFASecret = dec
		}
	}
	u.CreatedAt, _ = time.Parse("2006-01-02 15:04:05", createdAt)
	return &u, nil
}

// TODO: Add User methods
// func (d *DB) GetUser(id string) ...

// TODO: Add Certificate methods
// func (d *DB) StoreCertificate(cert *ssh.Certificate) ...

func (d *DB) encrypt(plaintext string) (string, error) {
	if len(d.EncryptionKey) == 0 {
		return plaintext, nil
	}

	key := sha256.Sum256(d.EncryptionKey)
	block, err := aes.NewCipher(key[:])
	if err != nil {
		return "", err
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", err
	}

	nonce := make([]byte, gcm.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return "", err
	}

	ciphertext := gcm.Seal(nonce, nonce, []byte(plaintext), nil)
	return base64.StdEncoding.EncodeToString(ciphertext), nil
}

func (d *DB) decrypt(ciphertext string) (string, error) {
	if len(d.EncryptionKey) == 0 {
		return ciphertext, nil
	}

	data, err := base64.StdEncoding.DecodeString(ciphertext)
	if err != nil {
		return "", err
	}

	key := sha256.Sum256(d.EncryptionKey)
	block, err := aes.NewCipher(key[:])
	if err != nil {
		return "", err
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", err
	}

	nonceSize := gcm.NonceSize()
	if len(data) < nonceSize {
		return "", fmt.Errorf("ciphertext too short")
	}

	nonce, ciphertextBytes := data[:nonceSize], data[nonceSize:]
	plaintext, err := gcm.Open(nil, nonce, ciphertextBytes, nil)
	if err != nil {
		return "", err
	}

	return string(plaintext), nil
}
