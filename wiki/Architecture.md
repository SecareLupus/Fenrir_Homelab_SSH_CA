# Fenrir Architecture

Fenrir follows a modular, three-tier architecture designed to protect your Root CA while remaining usable.

## 🏗 Three-Tier Deployment Model

### 🛡️ Tier 1: Online CA (Standard)

- **Deployment**: Single server handles both signing and web UI.
- **Storage**: Keys are encrypted at rest on the local filesystem.
- **Best For**: Internal-only networks where convenience is key.

### ❄️ Tier 2: Cold-Storage Root

- **Deployment**: Two containers on the same host. The Root container is kept stopped.
- **Security**: Root keys are only "online" during the issuing of a long-lived Intermediate certificate.
- **Best For**: Balanced security on a single machine.

### 🏔️ Tier 3: Isolated Root (Maximum Security)

- **Deployment**: Physical air-gap. The Root CA runs on an offline machine.
- **Workflow**: Signatures are moved via secure physical media (e.g., encrypted USB).
- **Best For**: High-risk environments where physical access is the only vector for root exfiltration.

---

## 📦 Core Components

| Component      | Role       | Description                                                     |
| :------------- | :--------- | :-------------------------------------------------------------- |
| **Fenrir**     | Server     | The central CA. Manages identity, policy, and signing.          |
| **Tyr**        | Client     | User CLI & Native GUI. Manages enrollment and local SSH config. |
| **Gleipnir**   | Host Agent | Syncs trust anchors and manages host-level security state.      |
| **pam_fenrir** | Extension  | PAM module for certificate-backed authentication and `sudo`.    |

---

## 🔐 Security Mechanisms

### Proof-of-Possession (PoP)

During certificate renewal, clients must sign a server-provided nonce with their private key. This ensures that a compromised API key alone cannot be used to refresh a stolen certificate.

### Hardware Backing

Private keys can be generated inside **HSMs or PKCS#11 tokens**. This makes private key exfiltration mathematically impossible, even with full OS compromise.

### Real-time Revocation (KRL)

Gleipnir agents periodically fetch a Key Revocation List (KRL). Revoking a user in the Fenrir UI results in near-instant access removal across the fleet.
