# Homelab SSH CA

A simple, single-binary SSH Certificate Authority designed for homelabs. It features a modern Web UI, SQLite backend, and native Go SSH implementation.

## 🏗 System Architecture

```mermaid
graph TB
    subgraph "High Security Zone (Offline)"
        RC[Root CA Instance]
        RK[(Root CA Keys)]
        RC --- RK
    end

    subgraph "DMZ / Internal Network (Online)"
        SC[SSH CA Server]
        DB[(SQLite DB)]
        IK[(Intermediate Keys)]
        SC --- DB
        SC --- IK
    end

    subgraph "Staff Workstations"
        CL[ssh-ca-client]
        SK[Hardware Security Key]
        CL --- SK
    end

    subgraph "Fleet Devices (Debian arm64)"
        AG[ssh-ca-agent]
        SH[sshd]
        AG --- SH
    end

    %% Interactions
    RC -- "Signs" --> SC
    CL -- "1. Auth / Enrolls" --> SC
    CL -- "2. PoP Challenge / Signed Cert" --> SC
    SC -- "KRL / CA PubKeys" --> AG
    AG -- "Updates Trust / Reloads" --> SH
    CL -- "SSH with Cert" --> SH
```

### 📝 Project Terminology

To ensure clarity across the ecosystem, we use the following standard terms:

| Term | Actor | Component | Use Case |
| :--- | :--- | :--- | :--- |
| **CA Server** | The Authority | `ssh-ca` | The "Brain". Signs certificates and manages the KRL. |
| **User Client** | Workstation | `ssh-ca-client` | Used by humans to get certificates to log into servers. |
| **Host Agent** | Target Device | `ssh-ca-agent` | Used by servers to trust the CA and identify themselves. |
| **PoP Renewal** | - | - | **Proof-of-Possession**: Renewing a certificate using a registered private key. |

### 🔄 Operational Flows

- **Enrollment (Initial)**: Requires a bootstrap secret (User Password or Host API Key). This associates a Public Key with an Identity (Username/Hostname) in the CA database.
- **Trust Sync**: By default, any device can fetch the CA Public Keys and KRL. In **Hardened Mode**, this requires an API Key.
- **Self-Healing Renewal**: Once a key is enrolled, it can be renewed via **Proof-of-Possession (PoP)**. The CA challenges the requester to sign a random nonce. If the signature is valid and the key is not distrusted, a new certificate is issued automatically. This allows workstations and servers to maintain their identities indefinitely without manual intervention.

## Features

- **Web UI**: Modern, dark-mode dashboard for managing certificates.
- **Single Binary**: No complex dependencies (MongoDB, Vault, etc.). Just one executable and a SQLite file.
- **Native SSH**: Uses `golang.org/x/crypto/ssh` for safe, standard-compliant certificate signing.
- **Host & User Keys**: Supports both user authentication and host verification.
- **MFA & Recovery**: Mandatory TOTP for admins with secure, single-use **Backup Codes**.
- **Passwordless Sudo**: Custom PAM module (`pam_ssh_ca`) for certificate-based sudo authentication.
- **Hardware Security**: Infrastructure for **PKCS#11 (HSM/YubiKey)** signing to ensure non-extractable CA keys.
- **Audit Friendly**: Detailed event logs with identity-based auditing.

## 📦 Installation
You can use the SSH CA in two ways:

### 1. Pre-built Binaries (Recommended)
Download the latest binaries for your platform from the [Releases](https://github.com/SecareLupus/Homelab_SSH_CA/releases) page.
- `ssh-ca-server-*`: The main CA server.
- `ssh-ca-client-*`: Command-line tool for users.
- `ssh-ca-agent-*`: Sync tool for target servers.
- `ssh-ca-gui-*`: Desktop control center (Linux).

### 2. Docker Images
Pull the official container from GHCR:
```bash
docker pull ghcr.io/secarelupus/ssh-ca:latest
```

## 🚀 Deployment Tiers

Choose the security tier that matches your homelab's risk profile. All tiers use the pre-built Docker image by default.

### 🛡️ Tier 1: Online CA (Max Convenience)
Everything runs in a single container. Good for internal-only labs.
1. Download `deploy/tier-1-online/docker-compose.yml`.
2. Run:
   ```bash
   docker compose up -d
   ```

### ❄️ Tier 2: Cold-Storage Root (Host Backed)
Two containers on one host. The Root CA remains stopped except during intermediate renewal.
1. Download `deploy/tier-2-shared-host/docker-compose.yml`.
2. Run:
   ```bash
   docker compose up -d
   ```

### 🔌 Tier 2+: Removable Root (USB Backed)
Same as Tier 2, but the Root keys live on a **removable USB drive**. High protection against host-level storage compromise.
```bash
# Set ROOT_DATA_DIR to your USB mount point
export ROOT_DATA_DIR=/mnt/usb_ca/root-ca-data
docker compose -f deploy/tier-2-shared-host/docker-compose.yml up root-ca
```

### 🏔️ Tier 3: Isolated Root (Max Security)
The Root CA runs on a dedicated offline machine. Highly recommended for production-grade homelabs.
1. **Prepare**: "Side-load" the Docker image to your offline machine using a USB drive (see `docs/RELEASE_PROCESS.md`).
2. **Deploy**: Use `deploy/tier-3-isolated/docker-compose.root.yml`.
3. **Workflow**: Refer to the [Offline Root Setup Workflow](.agent/workflows/offline-root-setup.md) for step-by-step signing instructions.

## 🛡️ Threat Mitigation Matrix

| Threat Category | Tier 1 | Tier 2 | Tier 2+ | Tier 3 | **+ Hardware Add-on** |
| :--- | :---: | :---: | :---: | :---: | :---: |
| **Daemon Software Bug** | ❌ Risk | ✅ Mitigated¹ | ✅ Mitigated¹ | ✅ Mitigated¹ | ❌ No change |
| **Host Root Compromise**| ❌ Full Loss | ❌ Loss | ⚠️ Partial² | ✅ Full | ✅ **Key safe** |
| **Key Exfiltration**    | ❌ Easy | ❌ Easy | ⚠️ If plugged in| ✅ Impossible | ✅ **Non-extractable** |
| **Session Hijacking**   | ❌ Risk | ✅ Mitigated³ | ✅ Mitigated³ | ✅ Mitigated³ | ⚠️ Touch required |
| **Physical Theft**      | ❌ Risk | ❌ Risk | ✅ Root on USB | ⚠️ Laptop theft | ✅ PIN required |

*¹ Root CA is stopped; bugs in the online intermediate cannot touch the root process.*  
*² If the host is compromised while the USB is unplugged, the Root identity remains safe.*  
*³ Even if an attacker hijacks the online server, they cannot reach the offline root process (stopped).*

### 🔑 Security Add-on: Hardware Keys (YubiKey/FIDO2)
Hardware keys can be added to **any tier** to ensure your CA private keys are **non-extractable**. Even if an attacker achieves full root access to your server, they cannot copy the private keys to another machine. Hardware keys transition your security from "Software-based" to "Signature-request based" (requiring a physical tap to sign).

### 4. First Login

1.  Open `http://localhost:8080`.
2.  Log in with username `admin`.
3.  **Important**: The password you use for the first time will be set as the admin password.

## 🛠 Configuration

### Client (User) Setup

1.  Download your certificate from the dashboard.
2.  Save it to `~/.ssh/id_ed25519-cert.pub`.
3.  Add the Certificate Authority's public key (from the dashboard) to your known hosts if you want to trust hosts signed by this CA.

### Server (Host) Setup

To allow users signed by this CA to log in:

1.  Copy the **User CA Key** from the dashboard.
2.  Save it to `/etc/ssh/user_ca.pub` on your target server.
3.  Edit `/etc/ssh/sshd_config`:
    ```ssh
    TrustedUserCAKeys /etc/ssh/user_ca.pub
    ```
4.  Restart sshd: `sudo systemctl restart sshd`.
### Advanced Hardening

| Feature | Env Variable | Description |
| :--- | :--- | :--- |
| **Hardened Sync** | `CA_HARDENED_SYNC=true` | Requires API Key to pull KRL/CA Keys. |
| **PKCS#11** | `PKCS11_MODULE` | Path to your HSM/YubiKey shared library. |

### PAM Module Setup (Passwordless Sudo)

To use your SSH certificate for sudo authentication:

1. Install dependencies: `sudo apt install libpam0g-dev` (on Debian/Ubuntu).
2. Build the module: `go build -buildmode=c-shared -o bin/pam_ssh_ca.so ./cmd/pam-ssh-ca`
2. Install to `/lib/security/`.
3. Configure `/etc/pam.d/sudo`:
   ```bash
   auth sufficient pam_ssh_ca.so
   ```

## Development

- **Database**: SQLite (`ssh-ca.db`)
- **Keys**: Stored in `ca-keys/` directory (created on first run).

## License

This project is licensed under the **GNU General Public License v3.0** - see the [LICENSE](LICENSE) file for details.
