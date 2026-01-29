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
	// Primary
	if u, err := loadOrGenKey(filepath.Join(keyDir, "user_ca"), "SSH CA USER KEY", cfg.CAPassphrase); err == nil {
		s.userSigners = append(s.userSigners, u)
	}
	if h, err := loadOrGenKey(filepath.Join(keyDir, "host_ca"), "SSH CA HOST KEY", cfg.CAPassphrase); err == nil {
		s.hostSigners = append(s.hostSigners, h)
	}
	// Rollover (Backup) - Only load if they exist
	if info, err := os.Stat(filepath.Join(keyDir, "user_ca.bak")); err == nil && !info.IsDir() {
		if u, err := loadOrGenKey(filepath.Join(keyDir, "user_ca.bak"), "SSH CA USER KEY", cfg.CAPassphrase); err == nil {
			s.userSigners = append(s.userSigners, u)
		}
	}
	if info, err := os.Stat(filepath.Join(keyDir, "host_ca.bak")); err == nil && !info.IsDir() {
		if h, err := loadOrGenKey(filepath.Join(keyDir, "host_ca.bak"), "SSH CA HOST KEY", cfg.CAPassphrase); err == nil {
			s.hostSigners = append(s.hostSigners, h)
		}
	}
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
	// Move active to bak
	os.Remove(filepath.Join(keyDir, "user_ca.bak"))
	os.Rename(filepath.Join(keyDir, "user_ca"), filepath.Join(keyDir, "user_ca.bak"))
	os.Remove(filepath.Join(keyDir, "host_ca.bak"))
	os.Rename(filepath.Join(keyDir, "host_ca"), filepath.Join(keyDir, "host_ca.bak"))

	// Regenerate
	_, err := loadOrGenKey(filepath.Join(keyDir, "user_ca"), "SSH CA USER KEY", cfg.CAPassphrase)
	if err != nil {
		return err
	}
	_, err = loadOrGenKey(filepath.Join(keyDir, "host_ca"), "SSH CA HOST KEY", cfg.CAPassphrase)
	if err != nil {
		return err
	}

	// Reload signers
	s.userSigners = nil
	s.hostSigners = nil
	s.loadSoftwareKeys(cfg)
	return nil
}

func loadOrGenKey(path, headers, passphrase string) (ssh.Signer, error) {
	// 1. Try to load
	content, err := os.ReadFile(path)
	if err == nil {
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
	if !os.IsNotExist(err) {
		return nil, fmt.Errorf("read key: %w", err)
	}

	// 2. Generate new ED25519 key
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
	}
	if err != nil {
		return nil, fmt.Errorf("marshal private key: %w", err)
	}

	// 4. Save to disk
	pemBytes := pem.EncodeToMemory(block)
	if err := os.WriteFile(path, pemBytes, 0600); err != nil {
		return nil, fmt.Errorf("write key: %w", err)
	}

	// 5. Also save public key for convenience
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
