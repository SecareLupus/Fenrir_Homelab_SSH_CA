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
	"crypto/ed25519"
	"crypto/rand"
	"encoding/binary"
	"encoding/pem"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"time"

	 "github.com/SecareLupus/Fenrir/internal/config"

	"golang.org/x/crypto/ssh"
)

// Service handles all CA operations
type Service struct {
	userSigners []ssh.Signer
	hostSigners []ssh.Signer
}

func (s *Service) GetUserCAPublicKey() ssh.PublicKey {
	if len(s.userSigners) == 0 {
		return nil
	}
	return s.userSigners[0].PublicKey()
}

func (s *Service) GetHostCAPublicKey() ssh.PublicKey {
	if len(s.hostSigners) == 0 {
		return nil
	}
	return s.hostSigners[0].PublicKey()
}

// New creates a new CA service, loading or generating keys as needed
func New(cfg *config.Config) (*Service, error) {
	keyDir := cfg.KeyPath
	if err := os.MkdirAll(keyDir, 0700); err != nil {
		return nil, fmt.Errorf("create key dir: %w", err)
	}

	s := &Service{}

	// 1. Load Software Keys (Fallback)
	userSigner, err := loadOrGenKey(filepath.Join(keyDir, "user_ca"), "SSH CA USER KEY", cfg.CAPassphrase)
	if err != nil {
		return nil, fmt.Errorf("user ca key: %w", err)
	}
	s.userSigners = append(s.userSigners, userSigner)

	hostSigner, err := loadOrGenKey(filepath.Join(keyDir, "host_ca"), "SSH CA HOST KEY", cfg.CAPassphrase)
	if err != nil {
		return nil, fmt.Errorf("host ca key: %w", err)
	}
	s.hostSigners = append(s.hostSigners, hostSigner)

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

func loadOrGenKey(path, headers, passphrase string) (ssh.Signer, error) {
	// 1. Try to load
	content, err := os.ReadFile(path)
	if err == nil {
		// Found key, parse it
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
		block, err = ssh.MarshalPrivateKey(priv, passphrase)
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

// SignUserCertificate signs a public key for user authentication
func (s *Service) SignUserCertificate(pubKey ssh.PublicKey, keyID string, principals []string, ttl uint64) (*ssh.Certificate, error) {
	if len(s.userSigners) == 0 {
		return nil, fmt.Errorf("no user signers available")
	}
	return s.sign(s.userSigners[0], pubKey, keyID, principals, ttl, ssh.UserCert)
}

// SignHostCertificate signs a public key for host authentication
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
	binary.Read(rand.Reader, binary.BigEndian, &serial)

	cert := &ssh.Certificate{
		KeyId:       keyID,
		Serial:      serial,
		CertType:    ssh.UserCert,
		Key:         pubKey,
		ValidAfter:  uint64(now.Unix()),
		ValidBefore: uint64(expires.Unix()),
		// Critical for intermediate CA: permit-X11-forwarding etc are not needed,
		// but we might want to restrict principals in future version.
		// For now, identity is what matters.
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
	binary.Read(rand.Reader, binary.BigEndian, &serial)

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
