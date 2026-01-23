package web

import (
	"ssh-ca/internal/db"

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
