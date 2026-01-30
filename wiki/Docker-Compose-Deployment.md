# Docker Compose Deployment

Fenrir provides pre-configured Docker Compose files for different security tiers. These are located in the `deploy/` directory of the repository.

## 🏗 Deployment Tiers

Fenrir is designed with a three-tier security model. Each tier has a corresponding directory in `deploy/`.

### Tier 1: Online CA (Standard)

The simplest setup where everything runs in a single container.

- **Location**: `deploy/tier-1-online/`
- **Setup**:
  ```bash
  cd deploy/tier-1-online
  docker-compose up -d
  ```

### Tier 2: Cold-Storage Root

Root and Intermediate CAs are separated. The Root container is only started when issuing new intermediate certificates.

- **Location**: `deploy/tier-2-shared-host/`

### Tier 3: Isolated Root

Maximum security with a physically air-gapped Root CA.

- **Location**: `deploy/tier-3-isolated/`

---

## ⚙️ Configuration (Environment Variables)

You can customize Fenrir by setting environment variables in your `docker-compose.yml` or a `.env` file.

### Core Settings

| Variable     | Description                                | Default     |
| :----------- | :----------------------------------------- | :---------- |
| `CA_MODE`    | Operation mode (`online` or `offline`)     | `online`    |
| `BIND_ADDR`  | Address the server binds to                | `:8080`     |
| `DB_PATH`    | Path to the SQLite database file           | `ssh-ca.db` |
| `KEY_PATH`   | Directory where CA keys are stored         | `ca-keys`   |
| `FENRIR_ENV` | Set to `production` for security hardening | `dev`       |

### Security & Encryption

| Variable                 | Description                           | Required            |
| :----------------------- | :------------------------------------ | :------------------ |
| `CA_PASSPHRASE`          | Passphrase to encrypt CA keys at rest | **Yes**             |
| `DB_ENCRYPTION_KEY`      | Key to encrypt sensitive DB fields    | **Yes**             |
| `SESSION_SECRET`         | Secret for cookie/session encryption  | **Yes**             |
| `INITIAL_ADMIN_PASSWORD` | Bootstrap password for 'admin' user   | **Yes** (First run) |

### Authentication (OIDC)

| Variable             | Description                          |
| :------------------- | :----------------------------------- |
| `OIDC_ENABLED`       | Set to `true` to enable SSO          |
| `OIDC_ISSUER_URL`    | Issuer URL (e.g., Authentik, Google) |
| `OIDC_CLIENT_ID`     | OAuth2 Client ID                     |
| `OIDC_CLIENT_SECRET` | OAuth2 Client Secret                 |
| `OIDC_REDIRECT_URL`  | Redirect URL (must match provider)   |

### WebAuthn (Passkeys/MFA)

| Variable                   | Description                       | Default                 |
| :------------------------- | :-------------------------------- | :---------------------- |
| `WEBAUTHN_RP_DISPLAY_NAME` | Name shown on the MFA prompt      | `Homelab SSH CA`        |
| `WEBAUTHN_RP_ID`           | Domain ID (e.g. `ca.example.com`) | `localhost`             |
| `WEBAUTHN_RP_ORIGIN`       | Full origin URL                   | `http://localhost:8080` |

### Hardware Security (PKCS#11/HSM)

| Variable             | Description                         |
| :------------------- | :---------------------------------- |
| `PKCS11_ENABLED`     | Set to `true` to enable HSM support |
| `PKCS11_MODULE`      | Path to the PKCS#11 library (`.so`) |
| `PKCS11_PIN`         | User PIN for the hardware token     |
| `PKCS11_TOKEN_LABEL` | Label of the hardware token         |

---

## 🚀 Quick Usage Tips

### Choosing a version

To use a specific version of Fenrir, set the `TAG` environment variable before running compose:

```bash
export TAG=v1.3.1
docker-compose up -d
```

### Persistence

The provided Tier 1 compose file uses a local `./data` directory mapped to `/data` in the container. Ensure this directory has appropriate permissions.
