# Fenrir Details Administrator Guide

## 🚀 Overview

Fenrir is a centralized SSH Certificate Authority (CA) designed to replace static SSH keys with short-lived, identity-based certificates.

This guide covers installation, configuration, key rotation, and day-to-day administration.

## 📦 Architecture Tiers

### Tier 1: Online CA (Testing/Internal)

- **Deployment**: Single container (`fenrir`) acting as Root CA.
- **Keys**: Stored on disk (`ca-keys/`).
- **Use Case**: Homelab prototyping, internal non-critical networks.

### Tier 3: Isolated Root (Production Hardening)

- **Deployment**:
  - **Offline Root**: Runs on an air-gapped machine (USB boot logic).
  - **Online Intermediate**: Runs on your server, holds only short-lived intermediate keys.
- **Workflow**: The Online instance generates a CSR, which must be physically transported to the Offline Root for signing.
- **Benefit**: Even if your server is compromised, the Root CA Identity is safe.

## 🛠 Configuration

### Environment Variables

| Variable                        | Description                              | Required?      |
| :------------------------------ | :--------------------------------------- | :------------- |
| `FENRIR_BIND_ADDR`              | Address to listen on (e.g., `:8080`)     | No             |
| `FENRIR_CA_PASSPHRASE`          | Passphrase to encrypt CA keys at rest    | **YES**        |
| `FENRIR_SESSION_SECRET`         | 32-byte hex string for cookie encryption | **YES** (Prod) |
| `FENRIR_INITIAL_ADMIN_PASSWORD` | Bootstrap password for 'admin' user      | First run only |

### OIDC (Single Sign-On)

Enable OIDC to allow users to login via Google, GitHub, Authentik, etc.

```bash
FENRIR_OIDC_ENABLED=true
FENRIR_OIDC_ISSUER_URL=https://auth.example.com
FENRIR_OIDC_CLIENT_ID=fenrir
FENRIR_OIDC_CLIENT_SECRET=...
FENRIR_OIDC_REDIRECT_URL=https://ca.example.com/auth/callback
```

_Note: Users are auto-created on first login if OIDC is successful._

### WebAuthn (Hardware Keys)

Enable Passkeys/YubiKeys for MFA.

```bash
FENRIR_WEBAUTHN_RP_DISPLAY_NAME="Fenrir SSH CA"
FENRIR_WEBAUTHN_RP_ID="ca.example.com"
FENRIR_WEBAUTHN_RP_ORIGIN="https://ca.example.com"
```

## 🔐 Security Operations

### 1. Key Rotation (Automated)

Fenrir automatically rotates its Intermediate CA keys every 180 days (configurable).

- **Grace Period**: The old key remains valid for verification for 24 hours to allow propagation.
- **Trust Bundles**: Clients and Hosts fetch the "Trust Bundle" (`/api/v1/ca/host`, `/api/v1/ca/user`) which contains **both** the active and valid-old keys.

### 2. Secret Rotation

Session encryption keys rotate every 30 days. This is seamless to users but invalidates sessions older than 30 days eventually.

### 3. Approval Workflows

For sensitive groups (e.g., `prod-access`), you can require Admin approval.

1. **Configure**: Set `requires_approval = true` for the group in the DB (or via UI in future).
2. **Flow**:
   - User requests cert -> Receives `202 Pending`.
   - Admin goes to `/admin/approvals` -> Clicks "Approve".
   - User runs `tyr` (or checks `/cert/pickup`) to get the cert.

### 4. Revocation (KRL)

If a user key or host is compromised:

1. Go to Admin Dashboard -> Users/Hosts.
2. Click **Revoke**.
3. This adds the Key Serial to the KRL.
4. Hosts (Gleipnir) sync the KRL every 5 minutes and will reject the key immediately.

## 🛡️ PAM & Group Access

Use the `pam_fenrir` module on hosts to enforce group-based access.

- **Policy**: "Only allow users in group `dev-team` to SSH into this host."
- **Setup**:
  1. Deploy `pam_fenrir.so`.
  2. Edit `/etc/pam.d/sshd`.
  3. Configure `authorized_principals` on the host.

## 🚨 Troubleshooting

- **Logs**: Check stdout/stderr. Logs are structured (JSON-like) for ingestion.
- **Audit**: View `/admin/audit` to see who signed what and when.
- **Health**: `/api/v1/health` checks DB connectivity and HSM/Signer health.
