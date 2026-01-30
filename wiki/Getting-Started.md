# Getting Started with Fenrir

Follow this guide to set up your first "Tier 1" (Online) Fenrir server and sign your first certificate.

## 1. Installation

### Using Docker (Recommended)

```bash
docker run -d \
  --name fenrir \
  -p 8080:8080 \
  -v fenrir-data:/data \
  -e FENRIR_CA_PASSPHRASE="your-secure-passphrase" \
  ghcr.io/secarelupus/fenrir:latest
```

### Native Binary

Download the latest release for your OS and run:

```bash
./fenrir server
```

## 2. Initial Setup

1.  Navigate to `http://localhost:8080` (or your server IP).
2.  Log in with the username `admin` and the initial password shown in the logs.
3.  Go to **Settings** and update your admin password and security preferences.

## 3. Client Setup (Tyr)

Download the **Tyr GUI** or CLI for your workstation.

### Onboarding Wizard

1.  Launch the Tyr GUI.
2.  The **Interactive Onboarding Wizard** will appear.
3.  Enter your Fenrir Server URL.
4.  Log in with your credentials.
5.  Tyr will securely store your API key in your system keychain.

## 4. Signing your first Cert

### Via GUI

1.  Click **Renew Now** on the Dashboard.
2.  If you have a FIDO key configured, touch it when prompted.
3.  Your status will change to **Certified**.

### Via CLI

```bash
tyr renew
```

## 5. Adding a Host (Gleipnir)

To allow SSH access into a machine using your new certs:

```bash
curl -sL https://ca.example.com/scripts/bootstrap.sh | sudo bash
```

This script installs Gleipnir, syncs the CA trust, and configures SSH to accept certificates.
