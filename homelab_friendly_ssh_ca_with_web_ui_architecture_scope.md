## Goal

Design an **open-source, homelab-friendly SSH Certificate Authority** with a **Web UI** that focuses on:

- Signing and renewing SSH certificates
- Low-to-middling operational complexity
- Good security defaults
- Clear upgrade paths (without becoming Vault / full zero-trust)

Transparent, zero-touch renewal is explicitly **out of scope for v1**, but the architecture must support it later.

---

## Core Principles

- Short-lived **user certificates**, longer-lived **host certificates**
- SSH CA built on **OpenSSH certificates** (no custom crypto)
- **Single binary + single database** deployment
- Opinionated defaults, minimal knobs
- Pluggable identity proofing (local auth first, OIDC later)
- Everything auditable

---

## High-Level Architecture

### Components

1. **CA Service (API Server)**
2. **Web UI (Admin + Self-Service)**
3. **Embedded Database (SQLite)**
4. **CA Key Material (online or intermediate)**
5. **Public Distribution Endpoints (CA pubkey, KRL)**
6. **Optional Minimal CLI**

All components may live in a single process for v1.

---

## 1. CA Service (API)

### Responsibilities

- SSH certificate signing and renewal
- Policy enforcement (roles, TTLs, principals)
- Identity verification (Pluggable interface: Local DB first, with OIDC hook for future)
- Audit logging
- KRL generation and publication
- Host certificate issuance

### Suggested Implementation

- Language: Go (static binary, mature SSH tooling)
- **Signing backend (v1): Native Go (`golang.org/x/crypto/ssh`)**
  - Use the native Go library to mint standard OpenSSH certificates.
  - Removes runtime dependency on `ssh-keygen`.
  - Safer and faster than shelling out.
  - Renewal is implemented as **re-issuing a fresh short-lived cert** (same enrolled public key fingerprint, same role constraints)
- No bespoke crypto: rely on the standard Go SSH library for certificate format and signing correctness

### Example Endpoints

- `POST /auth/login`
- `POST /keys/enroll`
- `POST /certs/sign`
- `POST /certs/renew`
- `POST /certs/revoke`
- `POST /hosts/sign`
- `GET /ca/public`
- `GET /krl`
- `GET /config/snippets`

---

## 2. Web UI

### Admin Views

- Users & groups
- Roles & policies
- Enrolled keys
- Certificate history
- Revocations
- Host inventory

### User Self-Service

- Upload or paste public keys
- Request / renew certificates
- View expiry
- Download certs and config snippets

### Design Goals

- Boring, explicit, readable
- No hidden automation
- All actions visible and auditable

---

## 3. Storage Model

### Database

- SQLite (starting default)
- Pluggable interface for future backends

### Core Tables

- Users
- Auth credentials (password hash, TOTP/WebAuthn metadata)
- Roles
- User–role mapping
- Public keys (fingerprint, label)
- Certificates (serial, principals, TTL, issuer, timestamps)
- Revocations (serials, fingerprints)
- Hosts
- Audit events

---

## 4. CA Security Tiers

### Tier 1: Online CA (Homelab Default)
- **Deployment**: Single container.
- **Key Management**: Both User and Host CA keys live on the active server.
- **Security**: Keys are encrypted at rest with a passphrase provided via environment variable. 
- **Use Case**: Maximum convenience for low-trust/internal-only homelabs.

### Tier 2: Cold-Storage Root (Host Backed)
- **Deployment**: Two containers on the same host (`root-ca` and `intermediate-ca`).
- **Key Management**: 
    - `intermediate-ca` is online and performs daily signing.
    - `root-ca` is **stopped** 99% of the time.
- **Security**: Protects against software bugs in the online daemon, but remains vulnerable to host-level compromise (host root can read stopped container volumes).
- **Use Case**: Basic security for users with a single server.

### Tier 2+: Removable Root (USB Backed)
- **Deployment**: Same as Tier 2, but the Root volumes are mapped to a physical USB drive.
- **Key Management**: 
    - Root keys are stored on an **externally mounted USB drive** (ideally encrypted).
    - The USB is **unplugged** when the Root CA is not in use.
- **Security**: Provides "Poor Man's Air-Gap". Even if the host is compromised, the Root identity is safe if the USB is physically removed.
- **Use Case**: Balanced high-security for single-server homelabs.

### Tier 3: Isolated Root (Air-Gapped)
- **Deployment**: `root-ca` runs on a dedicated, offline machine (e.g., an old laptop or RPi). `intermediate-ca` runs on the online server.
- **Key Management**: Root keys never touch a networked machine. 
- **Transfer**: CSRs and Certificates are moved via encrypted USB.
- **Security**: Maximum protection. Compromise of the online host allows revocation of the intermediate without risking the Root identity.
- **Use Case**: Production-grade or high-security personal infrastructures.

---

## 5. Security Extension: Hardware-Backed Keys

For users requiring tamper-proof key storage, the CA architecture supports (or will support) hardware integration across all tiers:

- **Non-Extractability**: CA private keys are generated inside a YubiKey or HSM and cannot be read by the host OS.
- **Physical Authorization**: Signing operations can be configured to require a physical "touch" on the security key, preventing automated/silent signature hijacks.
- **Support Paths**:
    - **YubiKey / HSM**: Integration via PKCS#11 for standard PIV slots.
    - **FIDO2**: Support for residential keys (requires custom `ssh.Signer` implementation).
    - **TPM**: Sealing software keys to the host's Trusted Platform Module.

By treating Hardware Keys as an **extension**, a user can run a **Tier 1 + YubiKey** setup (high convenience, key cannot be stolen) or a **Tier 3 + YubiKey** setup (the "Max Security" configuration).

## 5. Distribution Endpoints

Publicly accessible (HTTPS):

- User CA public key
- Host CA public key
- Key Revocation List (KRL)
- Optional known\_hosts bundle

---

## 6. Minimal CLI (Optional but Recommended)

Purpose:

- Reduce user error
- Provide a future path to transparent renewal

Initial Commands:

- `tool login`
- `tool enroll-key`
- `tool get-cert`
- `tool renew`

No daemon required for v1.

---

## Certificate Issuance Flow

1. User authenticates
2. Public key fingerprint validated
3. Role policies evaluated
4. Certificate signed with:
   - Principals
   - TTL
   - Extensions (permit-pty, forwarding, etc.)
5. Cert + metadata returned
6. Event written to audit log

---

## Renewal Flow

Same as issuance, with stricter checks:

- Authenticated session required
- Public key must already be enrolled
- Renewal window enforced
- Role still valid

Optional future enhancement:

- Proof-of-possession challenge

---

## Revocation & KRL

- Revoke by cert serial and/or key fingerprint
- Regenerate KRL
- Publish via HTTPS
- Designed for `RevokedKeys` sshd directive

---

## SSH Configuration Support

### Server (`sshd_config`) Snippets

- `TrustedUserCAKeys /etc/ssh/user_ca.pub`
- `RevokedKeys /etc/ssh/revoked.krl`
- Optional principals file

### Client (`ssh_config`) Snippets

- `IdentityFile ~/.ssh/id_ed25519`
- `CertificateFile ~/.ssh/id_ed25519-cert.pub`

UI should generate copy-paste-ready snippets per OS.

---

## Policy Model (Deliberately Simple)

### Role

- Allowed principals (static or templated)
- Max TTL
- Allowed extensions
- Hostname patterns (for host certs)

### User

- Assigned roles
- Group membership

No embedded policy language in v1.

---

## Deployment Model

### Homelab-Friendly Defaults

- docker-compose
- bind-mounted data directory
- Variant with built-in HTTPS via Traefik
  - Default assumes existing Reverse Proxy

### First-Run / Bootstrap

- **Automatic CA Generation**: Keys are generated on first startup if missing.
- **Admin Bootstrap**: First login as `admin` sets the administrator password.
- **Immediate Utility**: Dashboard displays CA public keys and setup instructions immediately after login.

---

## Security Guardrails

- MFA for admin accounts
- Encrypted CA keys at rest
- Rate limiting on signing endpoints
- Strict audit logging
- Clear warnings around online CA mode

---

## MVP Feature Set

1. Web UI (admin + self-service)
2. SSH user certificate issuance & renewal
3. KRL management
4. Host certificate support (Core feature)
5. Minimal CLI

---

## Future Extensions (Non-Goals for v1)

- Transparent renewal daemon
- PAM integration
- mTLS-based client auth
- OIDC / SSO
- Hardware-backed CA keys
- Policy DSL

---

## Positioning

"A simple, opinionated SSH CA for homelabs and small environments — without the operational overhead of Vault or full zero-trust platforms."

