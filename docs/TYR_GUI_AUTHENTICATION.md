# Tyr GUI Authentication & Settings

## Overview

Tyr GUI now supports **username/password login** and **persistent configuration**! No more manual API key management for desktop users.

## 🎯 New Features

### 1. **Settings Screen**
Access via system tray menu → "Settings" or first-run auto-redirect.

**Three Authentication Methods:**

- **Login Tab**: Direct username/password authentication (with MFA support)
- **API Key Tab**: Manual API key entry for users who prefer it
- **Advanced Tab**: SSH key path and type customization

### 2. **Persistent Configuration**
All settings are saved to `~/.tyr-gui-config.json` (permissions: 0600)

**Stored securely:**
- Fenrir server URL
- API key (encrypted at rest)
- SSH key path
- Key type preference

### 3. **MFA Support**
If your Fenrir account has TOTP enabled:
1. Enter username and password
2. MFA field appears automatically
3. Enter your 6-digit code or backup code

### 4. **Auto-Enrollment**
On first certificate request, Tyr GUI will:
1. Auto-generate SSH keys (if needed)
2. Enroll the key with Fenrir
3. Start auto-renewal background service

## 🚀 User Flow

### First Run Experience

1. **Launch Tyr GUI**
   ```bash
   ./tyr-gui
   ```

2. **Settings screen appears automatically** (no config detected)

3. **Choose authentication method:**

   **Option A: Username/Password** (Recommended)
   - Enter Fenrir URL (e.g., `http://fenrir.local:8080`)
   - Enter your username
   - Enter your password
   - (If MFA enabled) Enter TOTP code
   - Click "Login & Save"

   **Option B: API Key**
   - Enter Fenrir URL
   - Paste API key from Fenrir dashboard
   - Click "Save Configuration"

4. **Dashboard loads automatically**
   - Certificate status appears
   - Auto-renewal starts in background
   - System tray shows cert expiry countdown

### Subsequent Runs

Tyr GUI automatically:
- ✅ Loads saved configuration
- ✅ Opens dashboard directly
- ✅ Renews certificates when needed
- ✅ No login required!

## 🔧 Configuration Management

### Viewing Current Config
Navigate to "Settings" from:
- System tray → Settings
- Dashboard URL: `http://localhost:4500/settings`

### Changing Servers
1. Go to Settings
2. Update "Fenrir Server URL" in any tab
3. Re-authenticate (login or new API key)
4. Click Save

### Clearing All Settings
1. Go to Settings → Advanced tab
2. Click "Clear All Settings"
3. Tyr GUI will show first-run flow again

## 📁 File Locations

| File | Purpose | Permissions |
|------|---------|-------------|
| `~/.tyr-gui-config.json` | Saved settings | 0600 (owner only) |
| `~/.ssh/id_ed25519` | Default SSH key | Generated if missing |
| `~/.ssh/id_ed25519-cert.pub` | Signed certificate | Renewed automatically |

## 🔐 Security Considerations

### API Key Storage
- Stored in local config file with 0600 permissions
- Never transmitted except during authentication
- Cleared when "Clear All Settings" is used

### Password Handling
- **Never stored locally** - used only for authentication
- Exchanged for API key via `/api/auth/login`
- Password field clears after successful login

### MFA
- TOTP codes are sent securely to Fenrir
- Backup codes work seamlessly
- Invalid codes trigger re-prompt

## 🛠️ API Endpoints

Tyr GUI exposes a local HTTP server on `http://localhost:4500`:

| Endpoint | Method | Purpose |
|----------|--------|---------|
| `/` | GET | Dashboard view |
| `/settings` | GET | Settings/login view |
| `/api/status` | GET | Certificate status JSON |
| `/api/renew` | POST | Trigger manual renewal |
| `/api/config` | GET/POST/DELETE | Manage saved configuration |
| `/api/config/advanced` | POST | Update SSH key settings |
| `/api/login` | POST | Authenticate with Fenrir |
| `/api/launch` | GET | Launch SSH session to host |

## 🎨 UI Features

### Status Indicators
- **Green dot**: Certificate valid
- **Gray dot**: No certificate
- **Countdown timer**: Shows time until expiry

### Buttons
- **Renew Now**: Force immediate certificate renewal
- **Security Keys**: (Future) Manage hardware keys
- **Quick Connect**: Launch SSH to any host

### Theme
- Dark mode with glassmorphic design
- Responsive layout
- Smooth animations

## 📋 Troubleshooting

### "Settings screen keeps appearing"
- Check that `/api/login` or `/api/config` succeeded
- Verify `~/.tyr-gui-config.json` exists and has `api_key` field

### "Connection failed during login"
- Verify Fenrir server URL is correct and reachable
- Check server is running: `curl http://fenrir:8080/api/v1/health`
- Ensure no firewall blocking port 8080

### "Invalid credentials"
- Double-check username and password
- Ensure account is enabled in Fenrir admin panel
- Try logging in via web UI first

### "MFA code rejected"
- Verify system time is synchronized
- Use backup codes if TOTP is out of sync
- Check code is 6 digits and current

### "Certificate renewal fails"
- Check `/api/status` shows correct fingerprint
- Verify SSH key exists at configured path
- Try manual renewal from Settings

## 🔄 Migration from v1.0

If you used Tyr GUI before this update:

**Before (v1.0):**
- Hard-coded server URL
- No authentication stored
- Relied solely on PoP renewal

**After (Now):**
1. Launch Tyr GUI - settings screen appears
2. Enter your credentials using new login flow
3. Config is saved - you're done!

Your existing SSH keys and certificates continue to work.

## 🎉 Benefits

| Feature | Before | After |
|---------|--------|-------|
| **Setup** | Manual Web UI + API key | One-click login |
| **Config** | Code changes required | GUI settings screen |
| **Multi-server** | Recompile for each | Switch in settings |
| **Onboarding** | 5+ steps | 2 steps |
| **MFA** | Not supported | Full support |

---

## Example: Complete Setup Flow

```bash
# 1. Download Tyr GUI
curl -LO https://github.com/SecareLupus/Fenrir/releases/latest/download/tyr-gui-linux-amd64

# 2. Make executable
chmod +x tyr-gui-linux-amd64

# 3. Run
./tyr-gui-linux-amd64
# → Settings screen opens in browser

# 4. Fill in login form:
#    URL: http://192.168.1.100:8080
#    Username: alice
#    Password: ********
#    [Click "Login & Save"]

# 5. Done! Dashboard appears, auto-renewal active
```

**That's it!** No Web UI navigation, no API key copying, no config files to edit manually.
