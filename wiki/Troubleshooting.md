# Troubleshooting

## 🕸 Web UI & API

### "502 Bad Gateway" or "Connection Refused"

- Check if the Fenrir container/process is running.
- Ensure `FENRIR_BIND_ADDR` matches your network environment.
- Verify that your firewall allows traffic on port `8080` (default).

### OIDC Login Fails

- Ensure `redirect_uri` in your OIDC Provider matches `https://your-ca.com/auth/callback`.
- Check logs for "State Mismatch" errors (usually clock skew or cookie issues).

---

## 🖥 Tyr GUI

### Hotkey (`Ctrl+Shift+S`) not working

- On Linux (X11), ensure your user is in the `input` group if using raw hooks.
- On Wayland, global hotkeys may require specific compositor support.

### Keychain Access Errors

- Ensure a backend like `gnome-keyring` or `dbus-x11` is running.
- If running Tyr for the first time via SSH/Headless, use `tyr config` (CLI) instead of the GUI.

---

## 🔑 Certificates & SSH

### "Permission Denied (publickey)"

1.  Run `ssh-add -l` to see if your cert is in the agent.
2.  Run `tyr status` to check if the cert is expired.
3.  Check host logs: `journalctl -u ssh`. Look for "Invalid certificate" or "Principal mismatch".

### MFA/FIDO Touch not prompted

- Ensure your YubiKey is plugged in.
- Verify `libpam-u2f` or `libfido2` is installed on your workstation.

---

## 🚨 Auditing

All security events are stored in the internal SQLite database.

- **Location**: `data/fenrir.db`.
- **Viewing**: Use the **Audit Log** tab in the Admin UI or query the `audit_logs` table directly.
