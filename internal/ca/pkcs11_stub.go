//go:build !cgo
// +build !cgo

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

	"github.com/SecareLupus/Fenrir_Homelab_SSH_CA/internal/config"
	"golang.org/x/crypto/ssh"
)

// LoadPKCS11Signers provides a stub when CGO is disabled.
func LoadPKCS11Signers(cfg config.PKCS11Config) ([]ssh.Signer, []ssh.Signer, error) {
	if !cfg.Enabled {
		return nil, nil, nil
	}
	return nil, nil, fmt.Errorf("pkcs11 support requires CGO-enabled build")
}
