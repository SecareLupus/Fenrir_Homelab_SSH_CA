/*
 * Copyright (c) 2026 SecareLupus
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 */

package ca

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/binary"
	"encoding/hex"
	"encoding/pem"
	"fmt"
	"io"
	"log"
	"os"
	"path/filepath"
	"time"

	"github.com/SecareLupus/Fenrir_Homelab_SSH_CA/internal/auth"
	"github.com/SecareLupus/Fenrir_Homelab_SSH_CA/internal/config"

	"golang.org/x/crypto/ssh"
)

// Service handles core certificate authority operations, including signing
// user and host certificates, and managing root/intermediate keys.
type Service struct {
	userSigners []ssh.Signer
	hostSigners []ssh.Signer
}

// GetUserCAPublicKey returns the primary user-signing CA public key.
func (s *Service) GetUserCAPublicKey() ssh.PublicKey {
	if len(s.userSigners) == 0 {
		return nil
	}
	return s.userSigners[0].PublicKey()
}

// GetHostCAPublicKey returns the primary host-signing CA public key.
func (s *Service) GetHostCAPublicKey() ssh.PublicKey {
	if len(s.hostSigners) == 0 {
		return nil
	}
	return s.hostSigners[0].PublicKey()
}

// GetUserCAPublicBundle returns all current user-signing CA public keys (active + rollover)
func (s *Service) GetUserCAPublicBundle() []ssh.PublicKey {
	var keys []ssh.PublicKey
	for _, signer := range s.userSigners {
		keys = append(keys, signer.PublicKey())
	}
	return keys
}

// GetHostCAPublicBundle returns all current host-signing CA public keys (active + rollover)
func (s *Service) GetHostCAPublicBundle() []ssh.PublicKey {
	var keys []ssh.PublicKey
	for _, signer := range s.hostSigners {
		keys = append(keys, signer.PublicKey())
	}
	return keys
}

// New initializes a CA service. It loads software-based keys from the
// configured KeyPath and, if enabled, integrates hardware-based PKCS#11 keys.
func New(cfg *config.Config) (*Service, error) {
	keyDir := cfg.KeyPath
	if err := os.MkdirAll(keyDir, 0700); err != nil {
		return nil, fmt.Errorf("create key dir: %w", err)
	}

	s := &Service{}

	// 1. Load Software Keys (Active + Backup)
	s.loadSoftwareKeys(cfg)

	// 2. Load PKCS#11 Keys (Preferred)
	if cfg.PKCS11.Enabled {
		log.Printf("PKCS#11 enabled, attempting to load hardware keys for %s...", cfg.PKCS11.TokenLabel)
		pkUs, pkHs, err := LoadPKCS11Signers(cfg.PKCS11)
		if err != nil {
			log.Printf("Warning: PKCS#11 hardware initialization failed: %v", err)
			log.Printf("Falling back to software-only signing.")
		} else {
			// Prepend hardware signers so they are used first
			s.userSigners = append(pkUs, s.userSigners...)
			s.hostSigners = append(pkHs, s.hostSigners...)
		}
	}

	return s, nil
}

func (s *Service) loadSoftwareKeys(cfg *config.Config) {
	keyDir := cfg.KeyPath

	userPath := filepath.Join(keyDir, "user_ca")
	hostPath := filepath.Join(keyDir, "host_ca")
	userBak := userPath + ".bak"
	hostBak := hostPath + ".bak"

	// 1. Detect and recover from partial rotation
	userExists := fileExists(userPath)
	hostExists := fileExists(hostPath)
	userBakExists := fileExists(userBak)
	hostBakExists := fileExists(hostBak)

	if !userExists && userBakExists {
		log.Printf("Partial rotation detected for user_ca, recovering from .bak...")
		if err := os.Rename(userBak, userPath); err != nil {
			log.Printf("Warning: failed to recover user_ca: %v", err)
		} else {
			userExists = true
			userBakExists = false
		}
	}
	if !hostExists && hostBakExists {
		log.Printf("Partial rotation detected for host_ca, recovering from .bak...")
		if err := os.Rename(hostBak, hostPath); err != nil {
			log.Printf("Warning: failed to recover host_ca: %v", err)
		} else {
			hostExists = true
			hostBakExists = false
		}
	}

	// 2. Handle initial setup if both are missing
	if !userExists && !hostExists && !userBakExists && !hostBakExists {
		log.Printf("No CA keys found, generating new ones...")
		if _, err := GenerateCAKey(userPath, cfg.CAPassphrase); err != nil {
			log.Printf("Failed to generate user CA: %v", err)
		} else {
			userExists = true
		}
		if _, err := GenerateCAKey(hostPath, cfg.CAPassphrase); err != nil {
			log.Printf("Failed to generate host CA: %v", err)
		} else {
			hostExists = true
		}
	}

	// 3. Load Primary
	if userExists {
		if u, err := loadKey(userPath, cfg.CAPassphrase); err == nil {
			s.userSigners = append(s.userSigners, u)
		} else {
			log.Printf("Error loading primary user_ca: %v", err)
		}
	} else {
		log.Printf("Warning: primary user_ca missing")
	}

	if hostExists {
		if h, err := loadKey(hostPath, cfg.CAPassphrase); err == nil {
			s.hostSigners = append(s.hostSigners, h)
		} else {
			log.Printf("Error loading primary host_ca: %v", err)
		}
	} else {
		log.Printf("Warning: primary host_ca missing")
	}

	// 4. Load Rollover (Backup) - Only load if they exist
	if userBakExists {
		if u, err := loadKey(userBak, cfg.CAPassphrase); err == nil {
			s.userSigners = append(s.userSigners, u)
		}
	}
	if hostBakExists {
		if h, err := loadKey(hostBak, cfg.CAPassphrase); err == nil {
			s.hostSigners = append(s.hostSigners, h)
		}
	}
}

func fileExists(path string) bool {
	info, err := os.Stat(path)
	return err == nil && !info.IsDir()
}

func loadSigner(path, passphrase string) (ssh.Signer, error) {
	content, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	if passphrase != "" {
		return ssh.ParsePrivateKeyWithPassphrase(content, []byte(passphrase))
	}
	return ssh.ParsePrivateKey(content)
}

// RotateCAKeys triggers a key rotation. Current keys are moved to .bak and new ones generated.
func (s *Service) RotateCAKeys(cfg *config.Config) error {
	keyDir := cfg.KeyPath
	userPath := filepath.Join(keyDir, "user_ca")
	hostPath := filepath.Join(keyDir, "host_ca")
	userBak := userPath + ".bak"
	hostBak := hostPath + ".bak"
	userTmp := userPath + ".tmp"
	hostTmp := hostPath + ".tmp"

	// 1. Pre-check: Ensure current keys exist
	if !fileExists(userPath) || !fileExists(hostPath) {
		return fmt.Errorf("rotation failed: primary CA keys are missing")
	}

	// 2. Generate NEW keys into .tmp files first (Atomic preparation)
	log.Printf("Generating new CA keys for rotation...")
	if _, err := GenerateCAKey(userTmp, cfg.CAPassphrase); err != nil {
		return fmt.Errorf("failed to generate new user CA: %w", err)
	}
	if _, err := GenerateCAKey(hostTmp, cfg.CAPassphrase); err != nil {
		os.Remove(userTmp)
		os.Remove(userTmp + ".pub")
		return fmt.Errorf("failed to generate new host CA: %w", err)
	}

	// 3. Perform rotation (renames)
	// We move current to .bak, then .tmp to current.
	// We remove old .bak first.
	os.Remove(userBak)
	os.Remove(hostBak)

	log.Printf("Finalizing rotation sequence...")
	if err := os.Rename(userPath, userBak); err != nil {
		return fmt.Errorf("failed to move user_ca to bak: %w", err)
	}
	if err := os.Rename(hostPath, hostBak); err != nil {
		// Recovery attempt: move user_ca back if host_ca fails
		_ = os.Rename(userBak, userPath)
		return fmt.Errorf("failed to move host_ca to bak: %w", err)
	}

	// Now move .tmp to active
	if err := os.Rename(userTmp, userPath); err != nil {
		return fmt.Errorf("critical: failed to activate new user_ca (it exists as .tmp): %w", err)
	}
	if err := os.Rename(hostTmp, hostPath); err != nil {
		return fmt.Errorf("critical: failed to activate new host_ca (it exists as .tmp): %w", err)
	}

	// 4. Reload signers
	s.userSigners = nil
	s.hostSigners = nil
	s.loadSoftwareKeys(cfg)
	return nil
}

func loadKey(path, passphrase string) (ssh.Signer, error) {
	content, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	block, _ := pem.Decode(content)
	if block != nil && (block.Type == "ENCRYPTED PRIVATE KEY" || block.Type == "ENCRYPTED FENRIR KEY") {
		if passphrase == "" {
			return nil, fmt.Errorf("passphrase required for encrypted key")
		}
		var decrypted []byte
		if block.Type == "ENCRYPTED PRIVATE KEY" {
			// Backward compatibility for deprecated x509 encryption
			decrypted, err = x509.DecryptPEMBlock(block, []byte(passphrase))
		} else {
			// Modern AES-GCM encryption
			decrypted, err = decryptKey(block, passphrase)
		}
		if err != nil {
			return nil, fmt.Errorf("decrypt key: %w", err)
		}
		// Parse the decrypted PKCS#8 bytes
		privPEM := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: decrypted})
		defer auth.Zero(decrypted)
		return ssh.ParsePrivateKey(privPEM)
	}

	// Fallback to standard parsing
	if passphrase != "" {
		return ssh.ParsePrivateKeyWithPassphrase(content, []byte(passphrase))
	}
	return ssh.ParsePrivateKey(content)
}

func GenerateCAKey(path, passphrase string) (ssh.Signer, error) {
	// Generate new ED25519 key
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("generate key: %w", err)
	}

	var block *pem.Block
	if passphrase != "" {
		// Modern approach: PKCS#8 + AES-GCM with SHA256 KDF
		pkcs8Bytes, err := x509.MarshalPKCS8PrivateKey(priv)
		if err != nil {
			return nil, fmt.Errorf("marshal pkcs8: %w", err)
		}
		defer auth.Zero(pkcs8Bytes)
		block, err = encryptKey(pkcs8Bytes, passphrase)
		if err != nil {
			return nil, fmt.Errorf("encrypt key: %w", err)
		}
	} else {
		block, err = ssh.MarshalPrivateKey(priv, "")
		if err != nil {
			return nil, fmt.Errorf("marshal private key: %w", err)
		}
	}

	// Save to disk
	pemBytes := pem.EncodeToMemory(block)
	if err := os.WriteFile(path, pemBytes, 0600); err != nil {
		return nil, fmt.Errorf("write key: %w", err)
	}

	// Also save public key for convenience
	sshPub, err := ssh.NewPublicKey(priv.Public())
	if err == nil {
		_ = os.WriteFile(path+".pub", ssh.MarshalAuthorizedKey(sshPub), 0644)
	}

	return ssh.NewSignerFromKey(priv)
}

// HealthCheck verifies that the CA signers are operational.
// It attempts to sign a dummy payload using the primary user singer.
func (s *Service) HealthCheck() error {
	if len(s.userSigners) == 0 {
		return fmt.Errorf("no user signers available")
	}
	// Sign a dummy payload
	// rand.Reader is safe to use for testing signing
	_, err := s.userSigners[0].Sign(rand.Reader, []byte("health_check_payload"))
	if err != nil {
		return fmt.Errorf("signer check failed: %w", err)
	}
	return nil
}

// SignUserCertificate signs a public key for user authentication. It enforces
// identity-based key IDs and principal restrictions.
func (s *Service) SignUserCertificate(pubKey ssh.PublicKey, keyID string, principals []string, ttl uint64) (*ssh.Certificate, error) {
	if len(s.userSigners) == 0 {
		return nil, fmt.Errorf("no user signers available")
	}
	return s.sign(s.userSigners[0], pubKey, keyID, principals, ttl, ssh.UserCert)
}

// SignHostCertificate signs a public key for host identification.
func (s *Service) SignHostCertificate(pubKey ssh.PublicKey, keyID string, principals []string, ttl uint64) (*ssh.Certificate, error) {
	if len(s.hostSigners) == 0 {
		return nil, fmt.Errorf("no host signers available")
	}
	return s.sign(s.hostSigners[0], pubKey, keyID, principals, ttl, ssh.HostCert)
}

func (s *Service) sign(signer ssh.Signer, pubKey ssh.PublicKey, keyID string, principals []string, ttl uint64, certType uint32) (*ssh.Certificate, error) {
	now := time.Now()
	expires := now.Add(time.Duration(ttl) * time.Second)

	// Random serial number
	var serial uint64
	if err := binary.Read(rand.Reader, binary.BigEndian, &serial); err != nil {
		return nil, fmt.Errorf("read random serial: %w", err)
	}

	cert := &ssh.Certificate{
		KeyId:           keyID, // "username" or "hostname"
		Serial:          serial,
		CertType:        certType,
		Key:             pubKey,
		ValidPrincipals: principals,
		ValidAfter:      uint64(now.Unix()),
		ValidBefore:     uint64(expires.Unix()),
		Permissions: ssh.Permissions{
			Extensions: map[string]string{
				"permit-pty":              "",
				"permit-user-rc":          "",
				"permit-agent-forwarding": "",
				"permit-port-forwarding":  "",
			},
		},
	}

	// Host certs typically don't need extensions like permit-pty
	if certType == ssh.HostCert {
		cert.Permissions.Extensions = nil
	}

	if err := cert.SignCert(rand.Reader, signer); err != nil {
		return nil, fmt.Errorf("sign cert: %w", err)
	}

	return cert, nil
}

// SignIntermediateUserCertificate signs an intermediate CA key
func (s *Service) SignIntermediateUserCertificate(pubKey ssh.PublicKey, keyID string, ttl uint64) (*ssh.Certificate, error) {
	now := time.Now()
	expires := now.Add(time.Duration(ttl) * time.Second)

	var serial uint64
	if err := binary.Read(rand.Reader, binary.BigEndian, &serial); err != nil {
		return nil, fmt.Errorf("read random serial: %w", err)
	}

	cert := &ssh.Certificate{
		KeyId:       keyID,
		Serial:      serial,
		CertType:    ssh.UserCert,
		Key:         pubKey,
		ValidAfter:  uint64(now.Unix()),
		ValidBefore: uint64(expires.Unix()),
	}

	if len(s.userSigners) == 0 {
		return nil, fmt.Errorf("no user signers available")
	}
	if err := cert.SignCert(rand.Reader, s.userSigners[0]); err != nil {
		return nil, err
	}
	return cert, nil
}

// SignIntermediateHostCertificate signs an intermediate CA key
func (s *Service) SignIntermediateHostCertificate(pubKey ssh.PublicKey, keyID string, ttl uint64) (*ssh.Certificate, error) {
	now := time.Now()
	expires := now.Add(time.Duration(ttl) * time.Second)

	var serial uint64
	if err := binary.Read(rand.Reader, binary.BigEndian, &serial); err != nil {
		return nil, fmt.Errorf("read random serial: %w", err)
	}

	cert := &ssh.Certificate{
		KeyId:       keyID,
		Serial:      serial,
		CertType:    ssh.HostCert,
		Key:         pubKey,
		ValidAfter:  uint64(now.Unix()),
		ValidBefore: uint64(expires.Unix()),
	}

	if len(s.hostSigners) == 0 {
		return nil, fmt.Errorf("no host signers available")
	}
	if err := cert.SignCert(rand.Reader, s.hostSigners[0]); err != nil {
		return nil, err
	}
	return cert, nil
}

// --- Modern Encryption Helpers ---

func encryptKey(data []byte, passphrase string) (*pem.Block, error) {
	salt := make([]byte, 16)
	if _, err := io.ReadFull(rand.Reader, salt); err != nil {
		return nil, err
	}

	key := deriveKey(passphrase, salt)
	defer auth.Zero(key)
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}

	nonce := make([]byte, gcm.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, err
	}

	ciphertext := gcm.Seal(nonce, nonce, data, nil)

	return &pem.Block{
		Type: "ENCRYPTED FENRIR KEY",
		Headers: map[string]string{
			"Salt": hex.EncodeToString(salt),
			"KDF":  "SHA256-10000",
		},
		Bytes: ciphertext,
	}, nil
}

func decryptKey(block *pem.Block, passphrase string) ([]byte, error) {
	salt, err := hex.DecodeString(block.Headers["Salt"])
	if err != nil {
		return nil, fmt.Errorf("invalid salt")
	}

	key := deriveKey(passphrase, salt)
	defer auth.Zero(key)
	aesBlock, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	gcm, err := cipher.NewGCM(aesBlock)
	if err != nil {
		return nil, err
	}

	nonceSize := gcm.NonceSize()
	if len(block.Bytes) < nonceSize {
		return nil, fmt.Errorf("ciphertext too short")
	}

	nonce, ciphertext := block.Bytes[:nonceSize], block.Bytes[nonceSize:]
	return gcm.Open(nil, nonce, ciphertext, nil)
}

func deriveKey(passphrase string, salt []byte) []byte {
	// Simple but better-than-MD5 KDF
	key := []byte(passphrase)
	for i := 0; i < 10000; i++ {
		h := sha256.New()
		h.Write(salt)
		h.Write(key)
		oldKey := key
		key = h.Sum(nil)
		auth.Zero(oldKey)
	}
	return key
}
