# Fenrir SSH CA - Implementation Todo List (V2)

## Phase 6: Core Refinement & Security
- [x] **Admin Role Refactor**: Replace hardcoded `username == "admin"` checks with database-backed role lookups.
- [x] **Group-Based Access Control**: Implement groups and allow assigning certificates based on group membership.
- [x] **Granular TTL Policies**: Allow different max TTLs per role or user group.
- [x] **API Documentation**: Generate Swagger/OpenAPI specifications for all endpoints.

## Phase 7: Enterprise Integration
- [x] **OIDC/SSO Support**: Integrate with Authentik, Authelia, GitHub, or Google for Web UI login.
- [x] **WebAuthn Support**: Direct browser support for hardware keys (YubiKey/TouchID) as a primary factor.
- [x] **Audit Log Webhooks**: Send security events to Slack or Discord.

## Phase 8: Fleet Operations & Monitoring
- [x] **Host Inventory Dashboard**: View all registered hosts and their status.
- [x] **Fleet Bootstrap Script**: A one-liner script to join a new host.
- [x] **Prometheus Metrics**: Export signing activity and metrics.

## Phase 9: Client UX & Distribution
- [x] **Desktop Client Polish**: Enhance `tyr-gui` with system tray integration and login/settings UI.
- [x] **Client Authentication**: Implement username/password login and config persistence for `tyr` and `tyr-gui`.
- [x] **Automated Release Pipeline**: GitHub Actions for multi-platform binaries and Docker.
- [x] **Linux Distribution**: Automated `.deb` package creation.
- [x] **Version Injection**: Compile-time versioning via `ldflags`.

## Phase 10: Quality Assurance (Release v1.0.0 Ready)
- [x] **E2E Integration Tests**: Automated tests using Docker.
- [x] **Release Process Documentation**: Formalized steps for tagging and side-loading.
- [x] **Security Review**: Deep audit of intermediate key handling.

## Phase 11: Security & Reliability Hardening
- [x] **Signed Sessions**: Replace plaintext `session_user` cookie with signed or server-stored sessions.
- [x] **OIDC CSRF Protection**: Generate and validate per-login `state` (and nonce) for OIDC.
- [x] **Concurrent-Safe Auth Maps**: Protect `webauthnSessions` and PoP `challenges` with locking or a concurrent store.
- [x] **WebAuthn Nil Guard**: Disable WebAuthn routes or return a clear error when WebAuthn init fails.
- [x] **CSRF Protection for Admin POSTs**: Add CSRF tokens on state-changing endpoints that rely on cookies.

## 🚀 Future Roadmap (Post v1.0.0)
- [ ] **Native Installers (Windows/Mac)**: Create `.msi` or `.pkg` installers for better desktop integration.
- [x] **Credential Auto-Renewal**: Background daemon for Tyr (CLI) to automatically renew certs before expiry. (GUI has a renewal loop already.)
- [x] **Hardware CA Backend**: Direct PKCS#11 support for the Fenrir server to sign using HSMs.
