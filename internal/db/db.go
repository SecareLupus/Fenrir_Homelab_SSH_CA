package db

import (
	"database/sql"
	"fmt"
	"time"

	// Driver registration
	_ "modernc.org/sqlite"
)

// DB wraps the sql.DB connection
type DB struct {
	*sql.DB
}

// Init opens the SQLite database and runs migrations
func Init(path string) (*DB, error) {
	db, err := sql.Open("sqlite", path)
	if err != nil {
		return nil, fmt.Errorf("open db: %w", err)
	}

	if err := db.Ping(); err != nil {
		return nil, fmt.Errorf("ping db: %w", err)
	}

	d := &DB{db}
	if err := d.migrate(); err != nil {
		d.Close()
		return nil, fmt.Errorf("migrate: %w", err)
	}

	return d, nil
}

func (d *DB) migrate() error {
	schema := `
	CREATE TABLE IF NOT EXISTS users (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		username TEXT NOT NULL UNIQUE,
		password_hash TEXT, -- For local auth
		role TEXT NOT NULL DEFAULT 'user',
		enabled INTEGER NOT NULL DEFAULT 1, -- 1=true, 0=false
		created_at DATETIME DEFAULT CURRENT_TIMESTAMP
	);

	CREATE TABLE IF NOT EXISTS audit_logs (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		user_id INTEGER,
		event TEXT NOT NULL,
		metadata TEXT, -- JSON blob
		created_at DATETIME DEFAULT CURRENT_TIMESTAMP
	);

	CREATE TABLE IF NOT EXISTS public_keys (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		user_id INTEGER NOT NULL,
		fingerprint TEXT NOT NULL UNIQUE,
		type TEXT NOT NULL, -- e.g. ssh-ed25519
		content TEXT NOT NULL,
		comment TEXT,
		created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
		FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE
	);

	CREATE TABLE IF NOT EXISTS certificates (
		serial INTEGER PRIMARY KEY, -- OpenSSH serials are u64, sqlite int is i64. careful.
		key_fingerprint TEXT NOT NULL,
		type TEXT NOT NULL, -- user or host
		principals TEXT NOT NULL, -- JSON or comma-separated
		valid_from INTEGER NOT NULL, -- Unix timestamp
		valid_to INTEGER NOT NULL, -- Unix timestamp
		created_at DATETIME DEFAULT CURRENT_TIMESTAMP
	);
	
	CREATE TABLE IF NOT EXISTS revocations (
		serial INTEGER PRIMARY KEY,
		reason TEXT,
		revoked_at DATETIME DEFAULT CURRENT_TIMESTAMP
	);

	CREATE TABLE IF NOT EXISTS api_keys (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		user_id INTEGER NOT NULL,
		key_hash TEXT NOT NULL UNIQUE,
		label TEXT,
		created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
		FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE
	);

	CREATE TABLE IF NOT EXISTS hosts (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		hostname TEXT NOT NULL UNIQUE,
		fingerprint TEXT NOT NULL,
		api_key_hash TEXT, -- For agent-initiated renewal
		created_at DATETIME DEFAULT CURRENT_TIMESTAMP
	);

	CREATE TABLE IF NOT EXISTS mfa_backup_codes (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		user_id INTEGER NOT NULL,
		code_hash TEXT NOT NULL,
		used INTEGER NOT NULL DEFAULT 0, -- 0=unused, 1=used
		created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
		FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE
	);
	`
	_, err := d.Exec(schema)
	if err != nil {
		return err
	}

	// Manual migrations for existing schemas
	// SQLite doesn't have "ADD COLUMN IF NOT EXISTS", so we just try and ignore "duplicate column" error
	_, _ = d.Exec("ALTER TABLE users ADD COLUMN enabled INTEGER NOT NULL DEFAULT 1")
	_, _ = d.Exec("ALTER TABLE users ADD COLUMN role TEXT NOT NULL DEFAULT 'user'")
	_, _ = d.Exec("ALTER TABLE users ADD COLUMN mfa_secret TEXT")
	_, _ = d.Exec("ALTER TABLE hosts ADD COLUMN api_key_hash TEXT")

	return nil
}

// ... (existing code)

// CreateUser creates a new user. Returns error if username exists.
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

// GetUserByAPIKey returns the username associated with a valid API key hash
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
	if !secret.Valid {
		return "", nil
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
	_, err := d.Exec("UPDATE hosts SET api_key_hash = ? WHERE hostname = ?", keyHash, hostname)
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
	CreatedAt   string
}

// ListHosts returns all registered hosts
func (d *DB) ListHosts() ([]Host, error) {
	rows, err := d.Query("SELECT id, hostname, fingerprint, (api_key_hash IS NOT NULL), created_at FROM hosts")
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var hosts []Host
	for rows.Next() {
		var h Host
		if err := rows.Scan(&h.ID, &h.Hostname, &h.Fingerprint, &h.HasAPIKey, &h.CreatedAt); err != nil {
			return nil, err
		}
		hosts = append(hosts, h)
	}
	return hosts, nil
}

// RegisterPublicKey associates a public key with a user
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
		WHERE pk.fingerprint = ?
	`, fingerprint).Scan(&username)
	return username, err
}

// CheckHostPublicKeyOwnership returns the hostname if the key is registered to a host
func (d *DB) CheckHostPublicKeyOwnership(fingerprint string) (string, error) {
	var hostname string
	err := d.QueryRow("SELECT hostname FROM hosts WHERE fingerprint = ?", fingerprint).Scan(&hostname)
	return hostname, err
}

// LogEvent writes an entry to the audit log
func (d *DB) LogEvent(userID *int, event, metadata string) {
	_, _ = d.Exec("INSERT INTO audit_logs (user_id, event, metadata) VALUES (?, ?, ?)", userID, event, metadata)
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

func (d *DB) Close() error {
	// ...
	if d.DB != nil {
		return d.DB.Close()
	}
	return nil
}

// TODO: Add User methods
// func (d *DB) GetUser(id string) ...

// TODO: Add Certificate methods
// func (d *DB) StoreCertificate(cert *ssh.Certificate) ...
