# Release Process

This document outlines the release process for the Fenrir SSH CA ecosystem, including the server (Fenrir), client binaries (Tyr), agent (Gleipnir), and PAM modules (pam_fenrir).

## 1. Versioning Strategy
We use [Semantic Versioning (SemVer)](https://semver.org/).
- **Major**: Breaking changes.
- **Minor**: New features.
- **Patch**: Bug fixes and security updates.

## 2. Release Steps

### Step 1: Preparation
1.  Ensure `TODO.md` is updated and key features for the release are finished.
2.  Verify that the current `main` branch passes all tests.

### Step 2: Tagging
Create a signed git tag for the release:
```bash
git tag -a v1.0.0 -m "Release v1.0.0"
git push origin v1.0.0
```

### Step 3: Automated Build (CI)
The GitHub Action (`release.yml`) will automatically trigger when a tag matching `v*` is pushed. It will:
- Build binaries for Linux (amd64/arm64), Windows (amd64), and macOS (arm64).
- Compile the PAM shared library (`.so`).
- Build and push multi-arch Docker images to `ghcr.io/secarelupus/fenrir`.
- Create a **Draft Release** on GitHub.
Note: Fenrir Linux binaries are built with CGO enabled in CI to include PKCS#11 support.

### Step 4: Verification
1.  Download the binaries from the Draft Release.
2.  Test the `fenrir` server in a staging environment.
3.  Test `tyr` and `gleipnir` on your target machines.
4.  Verify checksums: `sha256sum -c checksums.txt`.

### Step 5: Publishing
1.  Once verified, edit the GitHub Release.
2.  Click **Publish Release**.

## 3. Artifact Distribution

| Component | Artifact Name | Description |
| :--- | :--- | :--- |
| **Server** | `fenrir` | Docker Image (`ghcr.io`) & Linux Binary |
| **Client (CLI)** | `tyr` | GitHub Release Binaries (Win/Mac/Linux) |
| **Agent** | `gleipnir` | GitHub Release Binaries (Linux/ARM64) |
| **GUI Client** | `tyr-gui` | GitHub Release Binaries (Linux) |
| **PAM Module** | `pam_fenrir` | Shared Library (`.so`) |

## 5. Air-Gapped / Tier 3 Deployment
For isolated machines that cannot reach GHCR:
1.  **On an online machine**:
    ```bash
    docker pull ghcr.io/secarelupus/fenrir:v1.0.0
    docker save ghcr.io/secarelupus/fenrir:v1.0.0 | gzip > fenrir-v1.0.0.tar.gz
    ```
2.  **Move the tarball** via encrypted USB.
3.  **On the offline host**:
    ```bash
    docker load < fenrir-v1.0.0.tar.gz
    ```
