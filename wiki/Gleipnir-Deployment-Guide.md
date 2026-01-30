# Gleipnir Deployment Guide

Gleipnir is the host-side security agent for Fenrir. It is responsible for synchronizing the CA Trust Bundle, maintaining the Key Revocation List (KRL), and automating host certificate renewal.

---

## 🚀 Standard Deployment

### 1. Automated Bootstrap (Recommended)

The easiest way to onboard a new host is using the interactive bootstrap script. This script downloads the binary, registers the host, and configures `sshd`.

```bash
curl -sL https://ca.example.com/scripts/bootstrap.sh | sudo bash
```

### 2. Manual Installation

For custom environments or configurations, you can install Gleipnir manually.

#### Get the Binary

Download the `gleipnir` binary for your architecture from the Fenrir releases page or your server's `/static/bin/` endpoint.

#### Registration

Register the host with the CA to receive an initial host certificate:

```bash
sudo ./gleipnir register --url https://ca.example.com --key YOUR_HOST_API_KEY
```

#### Systemd Service

Create a systemd unit at `/etc/systemd/system/gleipnir.service`:

```ini
[Unit]
Description=Gleipnir SSH CA Agent
After=network.target

[Service]
ExecStart=/usr/local/bin/gleipnir run --url https://ca.example.com --interval 5m --sync-pam
Restart=always
User=root

[Install]
WantedBy=multi-user.target
```

---

## ☁️ Stateless & Ephemeral Systems

In a stateless environment (e.g., NixOS, Fedora CoreOS, or Docker-based base images), persistence and initialization order are critical.

### 1. Persistence Requirements

While Gleipnir is mostly stateless, certain files **must** persist or be re-provisioned to maintain SSH access:

| Path                                     | Purpose            | Persistence Strategy              |
| :--------------------------------------- | :----------------- | :-------------------------------- |
| `/etc/ssh/trusted-user-ca-keys.pem`      | User CA Trust      | **Persist** or fetch on boot.     |
| `/etc/ssh/ssh_host_ed25519_key-cert.pub` | Host Identity Cert | **Persist** (linked to host key). |
| `/etc/ssh/revoked.krl`                   | Revocation List    | Re-fetch on boot (mandatory).     |

### 2. "Pre-Baking" the Image

To avoid a "chicken and egg" problem where you can't SSH into a new host to fix its configuration, we recommend "pre-baking" trust into your images:

1. **Inject the User CA**: Manually place the User CA public key at `/etc/ssh/trusted-user-ca-keys.pem` during image build.
2. **SSHD Config**: Ensure `sshd_config` contains:
   ```ssh
   TrustedUserCAKeys /etc/ssh/trusted-user-ca-keys.pem
   HostCertificate /etc/ssh/ssh_host_ed25519_key-cert.pub
   ```
3. **Provisioning**: On first boot, ensure your provisioning system (Cloud-init, Ignition) passes a `SSH_CA_API_KEY` environment variable so Gleipnir can register and fetch its first Host Cert immediately.

### 3. Running as a Sidecar

In containerized environments, run Gleipnir as a sidecar with a shared volume mounted at `/etc/ssh`. It will keep the KRL and Trust Bundle updated for the main SSHD process.
