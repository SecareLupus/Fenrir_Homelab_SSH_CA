//go:build cgo
// +build cgo

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
	"fmt"
	"log"

	"github.com/ThalesIgnite/crypto11"
	"github.com/SecareLupus/Fenrir_Homelab_SSH_CA/internal/config"
	"golang.org/x/crypto/ssh"
)

var pkcs11Contexts []*crypto11.Context

// LoadPKCS11Signers attempts to load signers from a hardware token.
// Returns userSigners and hostSigners slices.
func LoadPKCS11Signers(cfg config.PKCS11Config) ([]ssh.Signer, []ssh.Signer, error) {
	if !cfg.Enabled {
		return nil, nil, nil
	}
	if cfg.Module == "" {
		return nil, nil, fmt.Errorf("pkcs11 module path is required")
	}

	log.Printf("Initializing PKCS#11 module: %s", cfg.Module)

	ctx, err := crypto11.Configure(&crypto11.Config{
		Path:       cfg.Module,
		TokenLabel: cfg.TokenLabel,
		Pin:        cfg.PIN,
	})
	if err != nil {
		return nil, nil, fmt.Errorf("pkcs11 configure: %w", err)
	}
	// Keep context alive for the lifetime of the process.
	pkcs11Contexts = append(pkcs11Contexts, ctx)

	userLabel := cfg.UserKeyLabel
	if userLabel == "" {
		userLabel = cfg.KeyLabel
	}
	hostLabel := cfg.HostKeyLabel
	if hostLabel == "" {
		hostLabel = cfg.KeyLabel
	}
	if userLabel == "" || hostLabel == "" {
		return nil, nil, fmt.Errorf("pkcs11 key label is required (user/host)")
	}

	userSigner, err := signerFromLabel(ctx, userLabel)
	if err != nil {
		return nil, nil, fmt.Errorf("pkcs11 user key: %w", err)
	}
	hostSigner, err := signerFromLabel(ctx, hostLabel)
	if err != nil {
		return nil, nil, fmt.Errorf("pkcs11 host key: %w", err)
	}

	return []ssh.Signer{userSigner}, []ssh.Signer{hostSigner}, nil
}

func signerFromLabel(ctx *crypto11.Context, label string) (ssh.Signer, error) {
	signer, err := ctx.FindKeyPair(nil, []byte(label))
	if err != nil {
		return nil, err
	}
	if signer == nil {
		return nil, fmt.Errorf("key label not found: %s", label)
	}
	return ssh.NewSignerFromSigner(signer)
}
