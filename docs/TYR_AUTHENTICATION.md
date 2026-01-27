# Tyr Client Authentication Guide

## Overview

The `tyr` client supports three authentication methods for enrolling and renewing SSH certificates with a Fenrir server.

## Authentication Methods

### 1. Username/Password Login (Recommended for Interactive Use)

The easiest way to get started. Tyr will authenticate you with the Fenrir server and automatically obtain an API key for enrolling your SSH key.

**Basic usage:**
```bash
tyr --url http://fenrir.example.com:8080 --username alice
```

You'll be prompted for your password:
```
Password: ••••••••
```

**If MFA is enabled:**
```
Password: ••••••••
MFA code: 123456
✓ Successfully authenticated with Fenrir
Requesting certificate for /home/alice/.ssh/id_ed25519...
Success! Certificate saved.
```

**With inline password (not recommended for security):**
```bash
tyr --url http://fenrir.example.com:8080 --username alice --password mysecret
```

### 2. API Key (Recommended for Scripts and Automation)

For non-interactive use cases like CI/CD pipelines or cron jobs, use an API key.

**Generate an API key:**
1. Log into Fenrir's Web UI
2. Navigate to the Dashboard
3. Click "Generate API Key"
4. Copy and save the key

**Using the API key:**
```bash
# Save to a file
echo "your-api-key-here" > ~/.fenrir-api-key
chmod 600 ~/.fenrir-api-key

# Use with tyr
tyr --url http://fenrir.example.com:8080 --key-file ~/.fenrir-api-key
```

### 3. Proof-of-Possession (Automatic Renewal)

After your SSH key is enrolled (via method 1 or 2), subsequent certificate requests can use Proof-of-Possession (PoP) challenge-response. This "self-healing" mechanism allows automatic renewal without credentials.

**How it works:**
```bash
# No credentials needed!
tyr --url http://fenrir.example.com:8080
```

**Output:**
```
Requesting certificate for /home/alice/.ssh/id_ed25519...
PoP Challenge received. Touch your security key if prompted...
Success! Certificate saved.
```

The server:
1. Checks if the public key is already enrolled
2. Issues a random challenge nonce
3. Verifies the signature from your private key
4. Issues a new certificate

---

## Use Cases

| Use Case | Recommended Method |
|----------|-------------------|
| **First-time setup** | Username/Password |
| **Daily interactive use** | Proof-of-Possession |
| **Automation scripts** | API Key |
| **CI/CD pipelines** | API Key |
| **Scheduled renewals** | Proof-of-Possession |

## Security Notes

- **Passwords**: Never hardcode passwords in scripts. Use the prompt or API keys.
- **API Keys**: Store API keys in files with `600` permissions (owner read/write only).
- **MFA**: If your account has TOTP MFA enabled, you'll need to provide the code during username/password login.
- **PoP Challenges**: These are only valid for enrolled keys. First enrollment always requires authentication.

## Advanced Options

**Custom SSH key path:**
```bash
tyr --username alice --identity ~/.ssh/id_yubikey
```

**Hardware security keys:**
```bash
tyr --username alice --type ed25519-sk
```

**Custom Fenrir server:**
```bash
tyr --url https://fenrir.internal.example.com:8443 --username alice
```

---

## Troubleshooting

**"Invalid credentials"**
- Verify your username and password
- Check if your account is enabled in Fenrir

**"MFA required"**
- Ensure you're providing the TOTP code when prompted
- If using a backup code, make sure it hasn't been used before

**"Key not enrolled"**
- You need to enroll first using username/password or an API key
- PoP renewal only works for already-enrolled keys

**"Connection failed"**
- Verify the Fenrir server URL
- Check network connectivity
- Ensure the server is running

---

## Migration from API-Key-Only Workflow

If you previously used:
```bash
# Old method
tyr --key-file ~/.fenrir-api-key
```

You can now use:
```bash
# New method (interactive)
tyr --username alice
```

Your existing enrolled keys will continue to work with PoP renewal.
