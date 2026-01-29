# Fenrir User Guide

## 👋 Welcome

Fenrir is a tool that helps you connect to servers securely without managing permanent SSH keys. Instead of copying public keys to every server, you get a temporary "Certificate" that grants you access for a limited time (usually 12 hours).

## 💻 Getting Started

### Option 1: Tyr CLI (Command Line)

The `tyr` tool is the easiest way to manage your certificates.

#### 1. First Login

```bash
tyr login --url https://ca.example.com --username <your-username>
```

- You will be asked for your password (and TOTP code if enabled).
- Tyr will create a new SSH key pair automatically (`~/.ssh/id_ed25519_fenrir`).
- It creates a local configuration file so you don't need to type the URL again.

#### 2. Connect

Once logged in, Tyr configures your SSH agent. You can just verify status:

```bash
tyr status
```

Then use standard SSH:

```bash
ssh user@host
```

#### 3. Renewal

If your certificate expires, just run:

```bash
tyr renew
```

Note: Eventually, your session will expire (after 30 days usually), and you'll need to run `tyr login` again.

### Option 2: Tyr GUI (Desktop App)

If you prefer a visual interface (Linux only currently):

1. **Launch**: Run `tyr-gui`.
2. **Setup**: Click the "Settings" gear icon. Enter your CA URL, Username, and Password.
3. **Connect**: Only the "Connect" button needs to be clicked. The app stays in your system tray (top right).
   - **Green Icon**: You have a valid certificate.
   - **Red Icon**: Your certificate is expired.
4. **Quick Connect**: Right-click the tray icon to see a list of your frequently accessed servers.

### Option 3: Web Dashboard (Manual)

You can also manually download certificates if you don't want to use the tools.

1. Go to `https://ca.example.com`.
2. Log in.
3. Copy your SSH Public Key (`cat ~/.ssh/id_ed25519.pub`).
4. Paste it into the "Request Certificate" box.
5. Provide your password again for security.
6. **Download** the certificate file.
7. Save it as `~/.ssh/id_ed25519-cert.pub`.

## ⏳ Approval Workflows

Some access requires Administrator approval.

1. If you request a certificate and see "Request Pending", wait for an Admin to approve it.
2. Once approved, run `tyr renew` or check the "My Requests" page on the dashboard to pick it up.

## 🛠 Troubleshooting

**"Permission Denied (publickey)"**

- Check if your cert is expired: `ssh-keygen -Lf ~/.ssh/id_ed25519-cert.pub`
- Run `tyr status` to see if the agent is active.
- Ensure the server trusts the CA (contact your admin).

**"Proof of Possession Required"**

- This means your session allows renewal without password, but the server wants to verify you still hold the private key. `tyr` handles this automatically.
