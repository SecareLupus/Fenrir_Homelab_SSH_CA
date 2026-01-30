# Tyr GUI (Native App)

Phase 18-20 introduced a massive upgrade to the Tyr client, moving it from a browser utility to a first-class native desktop application.

## 🎨 Material Design 3 UI

The Tyr Control Center features a modern **Material Design 3 (M3) Dark Theme** aesthetic:

- **Tonal Palettes**: A unified color system using primary and surface tonal variants.
- **Dynamic Dashboard**: Instantly see your identity status, certificate expiry, and your 5 most recently used hosts.
- **Glassmorphism Lite**: Subtle transparency and background blurs for a premium feel.

## 🖥 Native Features

### System Tray & Quick Launch

- **Appindicator integration**: Tyr resides in your system tray (Linux/Windows/macOS).
- **Recent Connections Submenu**: Launch SSH sessions directly from the tray icon with one click.
- **Show/Hide Mirroring**: Toggle the window instantly from the tray.

### Global Hotkey

- **Default**: `Ctrl + Shift + S`
- **Function**: Instantly bring the Tyr Quick Launch window to the foreground from anywhere in your OS.

### Secure Keychain Storage

Tyr no longer stores your sensitive API keys in plaintext JSON files.

- **Linux**: Powered by the **Secret Service API** (Gnome Keyring / KWallet).
- **macOS/Windows**: Uses the system native Keychain and DPAPI.
- **Security**: Your credentials are encrypted and locked behind your OS user session.

## ⚡ Real-time Feedback

Tyr uses **Server-Sent Events (SSE)** for zero-latency UI updates:

- **Instant Renewal Feedback**: See your status change the moment a renewal completes.
- **FIDO Touch Prompts**: A smooth, pulsing overlay appears instantly when your hardware security key requires a physical touch to authorize a signature.

## 🛠 Automated SSH Config

Tyr automatically manages a managed block in your `~/.ssh/config`.

- **Cert Allocation**: Automatically ensures `CertificateFile` and `IdentityFile` are mapped for all outgoing SSH connections (`Host *`).
- **Zero Config**: Just run Tyr, and your native `ssh` command becomes "CA-aware" immediately.
