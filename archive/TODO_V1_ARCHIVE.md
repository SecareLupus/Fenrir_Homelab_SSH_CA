# SSH CA - Implementation Todo List

## Phase 1: Foundation & User Security (Completed ✅)
- [x] Native Go SSH CA Backend (User/Host keys)
- [x] SQLite Storage Layer
- [x] Web UI for Login & User Dashboard
- [x] API Key Enrollment (Key-file based)
- [x] Proof of Possession (PoP) Renewal Flow
- [x] User Management Dashboard (Enable/Disable users)
- [x] Audit Log Backend (Database tracking)

## Phase 2: Visibility & Host Trust (Completed ✅)
- [x] **Audit Log UI**: View security events and signing history in the Admin panel.
- [x] **Host Certificate Management**:
    - [x] Endpoint for host key signing.
    - [x] UI for Host Signing (Admin only).
    - [x] Support for host-specific principals (FQDNs/IPs).

## Phase 3: Infrastructure & Polish (Completed ✅)
- [x] **Revocation Management**:
    - [x] `GET /krl` endpoint to serve plain-text RevokedKeys list.
    - [x] UI to revoke specific keys from the Audit Log.
- [x] **UX Polish**:
    - [x] Copy-paste `sshd_config` snippets in the UI.
    - [x] Contextual help for server/client setup.

## Phase 4: Hardening (Completed ✅)
- [x] **MFA Support**:
    - [x] TOTP (Google Authenticator) enrollment for admins.
    - [x] Mandatory MFA verification on login for enabled accounts.

## Phase 5: Hardware Security (Completed ✅)
- [x] **FIDO/Security Key Support**:
    - [x] CLI support for generating `ed25519-sk` keys.
    - [x] CLI support for signing PoP challenges via `ssh-agent` (required for hardware keys).
    - [x] Server-side verification for security-key signatures.
