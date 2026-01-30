# CLI Tool Reference

Fenrir consists of three main command-line utilities.

## 🦊 Fenrir (Server)

The core CA engine and Web UI.

| Command              | Description                                     |
| :------------------- | :---------------------------------------------- |
| `fenrir server`      | Starts the CA server and Web UI.                |
| `fenrir ca gen`      | Generates a new Root CA (Offline).              |
| `fenrir ca sign-csr` | Signs an Intermediate CSR (Offline Root logic). |
| `fenrir user add`    | Manually add a user (CLI backup).               |

**Common Flags:**

- `--config`: Path to config file (default: `./config.yml`).
- `--dev`: Start in development mode (log-level: debug).

---

## 🦅 Tyr (Client)

User-facing workstation tool.

| Command             | Description                             |
| :------------------ | :-------------------------------------- |
| `tyr renew`         | Refreshes your SSH certificate.         |
| `tyr status`        | Shows current identity and cert expiry. |
| `tyr launch <host>` | Quick-opens an SSH session to a target. |
| `tyr config`        | Interactive setup for the CLI/GUI.      |

**Common Flags:**

- `--gui`: Launch the native control center window.
- `--force`: Force a renewal even if cert is still valid.

---

## ⛓️ Gleipnir (Agent)

Host-side security daemon.

| Command            | Description                             |
| :----------------- | :-------------------------------------- |
| `gleipnir run`     | Starts the agent in the foreground.     |
| `gleipnir install` | Installs Gleipnir as a systemd service. |
| `gleipnir sync`    | Manually trigger a Trust/KRL sync.      |

**Common Flags:**

- `--server`: Fenrir server URL.
- `--sync-pam`: Enable/disable automatic PAM module updates.
- `--interval`: Sync frequency (default: `5m`).
