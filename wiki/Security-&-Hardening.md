# Security & Hardening

Fenrir provides several layers of protection to ensure your identity infrastructure remains robust.

## 🔐 Passwordless Sudo with `pam_fenrir`

The `pam_fenrir` module allows you to authorize `sudo` via SSH certificates instead of passwords.

### How it works

1.  User initiates `sudo`.
2.  `pam_fenrir` challenges the user's local `ssh-agent`.
3.  User authorizes (often via FIDO touch).
4.  `pam_fenrir` verifies the signature and checks if the certificate contains the authorized group principal (e.g., `sudo-enabled`).

### Setup

Gleipnir handles the deployment of this module automatically if `--sync-pam=true` is set.

## 🔑 CA Key Rotation

Protecting the CA private keys is critical. Fenrir rotates Intermediate keys automatically.

- **Intermediate Rotation**: Occurs every 180 days.
- **Root Rotation**: Manual process recommended every 1-2 years.
- **Safety**: Rotation is atomic; the system keeps the previous key in a "Trust Bundle" for 24 hours to prevent lockout during propagation.

## 🏗 Hardware Security Modules (HSM)

For maximum security, CA keys should never exist in system memory.

### PKCS#11 Support

Fenrir can interface with any PKCS#11 compatible device:

- **YubiKey 5 (PIV)**
- **TPM 2.0 (via tpm2-pkcs11)**
- **SoftHSM (for testing)**

**Configuration:**
Set `FENRIR_PKCS11_MODULE` and `FENRIR_PKCS11_PIN` in your environment.

## 🚫 Revocation (KRL)

Revocation is instant and global.

1.  **Revoke** a user or host in the Fenrir Web UI.
2.  A new **Key Revocation List (KRL)** is generated.
3.  Gleipnir agents fetch the new KRL.
4.  Subsequent SSH or `sudo` attempts with the revoked key will be rejected immediately.
