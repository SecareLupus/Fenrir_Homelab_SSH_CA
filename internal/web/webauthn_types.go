/*
 * Copyright (c) 2026 SecareLupus
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 */

package web

import (
	 "github.com/SecareLupus/Fenrir_Homelab_SSH_CA/internal/db"

	"github.com/go-webauthn/webauthn/webauthn"
)

// webauthnUser wraps db.User to implement webauthn.User interface
type webauthnUser struct {
	*db.User
	creds []db.WebAuthnCredential
}

func (u *webauthnUser) WebAuthnID() []byte {
	return []byte(u.Username)
}

func (u *webauthnUser) WebAuthnName() string {
	return u.Username
}

func (u *webauthnUser) WebAuthnDisplayName() string {
	return u.Username
}

func (u *webauthnUser) WebAuthnIcon() string {
	return ""
}

func (u *webauthnUser) WebAuthnCredentials() []webauthn.Credential {
	res := make([]webauthn.Credential, len(u.creds))
	for i, c := range u.creds {
		res[i] = webauthn.Credential{
			ID:              c.CredentialID,
			PublicKey:       c.PublicKey,
			AttestationType: c.AttestationType,
			Transport:       nil,
			Flags: webauthn.CredentialFlags{
				UserPresent:    true,
				UserVerified:   true,
				BackupEligible: true,
				BackupState:    false,
			},
			Authenticator: webauthn.Authenticator{
				AAGUID:    c.AAGUID,
				SignCount: uint32(c.SignCount),
			},
		}
	}
	return res
}
