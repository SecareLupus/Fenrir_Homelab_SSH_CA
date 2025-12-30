---
description: How to set up an offline root CA with an online intermediate
---

# Offline Root + Online Intermediate Workflow

This workflow allows you to maintain a high-security "offline" root CA that signs intermediate certificates for your "online" CA. Target hosts trust the Root CA, allowing you to rotate the Intermediate CA without touching the hosts.

## Phase 1: Initialize Offline Root

1. Create a dedicated directory for the offline root.
2. Start the SSH CA in `offline` mode.

// turbo
```bash
# Run this on your high-security/offline machine
export CA_MODE=offline
export KEY_PATH=./root-ca-keys
export DB_PATH=./root-ca.db
export BIND_ADDR=:8081
# Build and run (or use existing binary)
go build -o ssh-ca ./cmd/server
./ssh-ca
```

3. Log in to the UI at `http://localhost:8081`.
4. The first login will bootstrap the `admin` user.
5. Note the **Root User CA Public Key** and **Root Host CA Public Key** from the dashboard. These are what your "Fleet Devices" will trust.

## Phase 2: Initialize Online Intermediate

1. On your online server, initialize a standard instance.

// turbo
```bash
# Run this on your online server
export CA_MODE=online
export KEY_PATH=./online-ca-keys
export DB_PATH=./online-ca.db
# Run the server to generate its own keypair
./ssh-ca
```

2. Locate the generated public keys on the online server:
   - `./online-ca-keys/user_ca.pub`
   - `./online-ca-keys/host_ca.pub`

## Phase 3: Root Signs Intermediate

1. In the **Offline Root UI** (`/admin/offline`), paste the `user_ca.pub` from the online server into the signing tool.
2. Download the resulting `intermediate-user-cert.pub`.
3. Repeat for `host_ca.pub` and download `intermediate-host-cert.pub`.

## Phase 4: Configure Online Server to use Intermediate Certificates

1. Move the signed certificates to the online server's key directory.
2. Rename them to reflect that they are certificates for the CA keys:
   - `intermediate-user-cert.pub` -> `./online-ca-keys/user_ca-cert.pub`
   - `intermediate-host-cert.pub` -> `./online-ca-keys/host_ca-cert.pub`

*(Note: The current implementation of `ssh-ca` uses the private keys directly for signing. To support chaining, `sshd` on target hosts must be configured to trust the ROOT keys, and clients/hosts must present their certificates signed by the intermediate, accompanied by the intermediate's own root-signed certificate. For OpenSSH, this usually means target hosts trust the Root, and you use the Intermediate keys as the CA. Rotation is handled by renewing the Intermediate's certificate.)*

## Phase 5: Shutdown Offline Root

1. Once the intermediate certificates are issued, stop the offline root service and power off the machine.
2. Secure the `root-ca-keys` directory (e.g., on an encrypted USB drive).

---

## 🚨 Emergency: Intermediate Compromise & Surgical Recovery

If your online intermediate server is compromised, use this process to invalidate the stolen keys while preserving your authorized user list.

### 1. Identify and Revoke (Offline)
1. Determine the suspected **Compromise Start Time**.
2. Power on the **Offline Root**.
3. In the Offline UI, **Revoke** the old Intermediate CA Key.
4. Download the new **KRL**.
5. Deploy the KRL to your fleet hosts immediately. This kills all certificates signed by the compromised key.

### 2. Surgical Key Rotation (Online)
Instead of wiping the entire volume, you only rotate the CA keys:

```bash
# 1. Stop the online service
docker compose -f docker-compose.offline.yml stop intermediate-ca

# 2. Delete ONLY the compromised keys (keep the ssh-ca.db!)
# (Assuming your volumes are in ./online-ca-data-v1)
rm ./online-ca-data-v1/keys/*

# 3. Start the service
docker compose -f docker-compose.offline.yml start intermediate-ca
```
On startup, the CA will generate fresh keys. Follow Phase 3 & 4 again to have the root sign these new keys.

### 3. Identity Audit
1. Log in to the Online CA (your user accounts and public keys are still there).
2. Go to **Admin Panel** -> **Identity Audit**.
3. Enter your **Compromise Start Time**.
4. The system will show every User and Public Key created since the compromise.
5. Manually verify or delete any suspicious entries.

Once complete, your CA is back online with its original identity store, but all stolen material is useless.
