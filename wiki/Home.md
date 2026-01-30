# Welcome to Fenrir SSH CA

Fenrir is a Norse-themed, security-first SSH Certificate Authority designed specifically for homelabs and internal infrastructure. It replaces static, permanent SSH keys with short-lived, identity-verified certificates.

---

## 🏛 The Vision

Fenrir aims to bring enterprise-grade security (like BeyondCorp/Zero Trust) to the homelab without the complexity of enterprise tools. It balances high-security deployment models (air-gapped roots) with modern, user-friendly client experiences.

## 🚀 Key Features

- **🌐 Modern Web UI**: Material Design 3 dashboard for certificate management and administration.
- **🖥 Native Desktop Client (Tyr)**: A native GUI with system tray integration, global hotkeys, and secure keychain storage.
- **🛡 Hardware Security (PKCS#11)**: Back your CA keys with hardware (Yubikeys, HSMS, TPMs).
- **🔐 Advanced Authentication**: Support for OIDC (SSO), WebAuthn (Passkeys), and Proof-of-Possession renewals.
- **⚙️ Automated Host Security**: The Gleipnir agent and `pam_fenrir` module provide passwordless, certificate-backed `sudo`.
- **🏗 Three-Tier Architecture**: Choose your level of isolation from "Simple Online" to "Physically Air-Gapped".

---

## 📖 Wiki Navigation

- **[Getting Started](Getting-Started)**: Install Fenrir and issue your first certificate.
- **[Architecture](Architecture)**: Learn how Fenrir protects your keys and identity.
- **[Docker Compose Deployment](Docker-Compose-Deployment)**: Guide for tiered deployments and configuration.
  - **[Tier 3 Isolated Root Setup](Tier-3-Isolated-Root-Setup)**: Deep-dive into air-gapped security.
  - **[Gleipnir Deployment Guide](Gleipnir-Deployment-Guide)**: How to secure your fleet hosts.
- **[Tyr GUI (Native App)](<Tyr-GUI-(Native-App)>)**: Explore the new native client features.
- **[Security & Hardening](Security-&-Hardening)**: Setup PAM, CA Rotation, and HSM support.
- **[CLI Tool Reference](CLI-Tool-Reference)**: Detailed usage for Fenrir, Tyr, and Gleipnir.
- **[Troubleshooting](Troubleshooting)**: Solve common issues and audit your setup.
