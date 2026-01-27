# Release Process

This document outlines the release process for the SSH CA ecosystem, including the server, client binaries, agent, and PAM modules.

## 1. Versioning Strategy
We use [Semantic Versioning (SemVer)](https://semver.org/).
- **Major**: Breaking changes (e.g., protocol changes, database migrations that are not backward compatible).
- **Minor**: New features (e.g., new MFA methods, new CLI commands).
- **Patch**: Bug fixes and security updates.

## 2. Release Steps

### Step 1: Preparation
1.  Ensure `TODO.md` is updated and key features for the release are finished.
2.  Update the `CHANGELOG.md` (if we start one) or use GitHub's automated release notes.
3.  Verify that the current `main` branch passes all tests.

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
- Build and push multi-arch Docker images to `ghcr.io`.
- Create a **Draft Release** on GitHub with all binaries attached as artifacts.

### Step 4: Verification
1.  Download the binaries from the Draft Release.
2.  Test the `ssh-ca-server` in a staging environment.
3.  Test the `ssh-ca-client` and `ssh-ca-agent` on at least one Linux and one Windows machine.
4.  Verify the checksums: `sha256sum -c checksums.txt`.

### Step 5: Publishing
1.  Once verified, edit the GitHub Release.
2.  Review the automated release notes.
3.  Click **Publish Release**.

## 3. Artifact Distribution

| Artifact | Distribution Method |
| :--- | :--- |
| **Server** | Docker Image (`ghcr.io`), Linux Binary |
| **Client (CLI)** | GitHub Release Binaries (Win/Mac/Linux) |
| **Agent** | GitHub Release Binaries (Linux/ARM64) |
| **GUI Client** | GitHub Release Binaries (Linux) |
| **PAM Module** | GitHub Release Shared Library (`.so`) |

## 4. Future Improvements
- **Debian Repository**: Automate `.deb` package creation and hosting.
- **Homebrew Tap**: Create a formula for macOS users.
- **Windows Installer**: Create an `.msi` or `.exe` installer for the GUI client.
- **Auto-Update**: Implement version check and self-update in the client/agent.
