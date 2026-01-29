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

## Phase 12: Immediate Security Remediation (Critical)

- [x] **Fix Path Traversal**: Sanitize template paths in `renderPage` to prevent directory traversal.
- [x] **Secure Session Secrets**: Fail-fast on secret generation failure and remove hardcoded fallbacks.
- [x] **Reverse Proxy Support**: Fix `Secure` cookie flag by detecting `X-Forwarded-Proto`.
- [x] **Strict Environment Check**: Require critical variables (`SESSION_SECRET`, `CA_PASSPHRASE`) on startup in production.

## Phase 13: Hardening & Validation

- [x] **Input Validation**: Implement regex validation for principals and strict TTL enforcement.
- [x] **Modernize CA Crypto**: Replace deprecated `x509.EncryptPEMBlock` with PKCS#8 or modern equivalents.
- [x] **API Key Strengthening**: Upgrade API key hashing from bare SHA256 to HMAC or bcrypt.
- [x] **Secure Bootstrap**: Require bootstrap token for first admin creation.
- [x] **Rate Limiting**: Add login and MFA rate limiting.

## Phase 14: Quality & Observability

- [ ] **CI/CD Integration**: Automate unit and E2E tests on pull requests.
- [ ] **Increase Test Coverage**: Target ≥70% unit test coverage, focusing on auth handlers.
- [ ] **Code Documentation**: Add doc comments to all public functions and types for better Godoc support.
- [ ] **Architecture Documentation**: Create high-level design docs for the three-tier deployment model.
- [ ] **Error Handling Audit**: Review codebase for silent failures (ignored errors in crypto/DB operations).
- [ ] **Secret Zeroization**: Securely clear sensitive buffers (keys, passphrases) from memory after use.
- [ ] **Security Headers**: Implement HSTS, CSP, and X-Frame-Options.
- [x] **Container Hardening**: Update Dockerfile to run as non-root user.

## Phase 15: Enterprise Reliability

- [ ] **Secret Rotation**: Implement a workflow for rotating session secrets and CA passphrases.
- [ ] **Approval Workflows**: Optional request/approval flow for sensitive certificates.
- [ ] **Key Rotation**: Infrastructure for rotating the CA root/intermediate keys.
- [ ] **Webhook Hardening**: Add timeouts and retry logic to prevent DB-level hangs during external calls.
- [ ] **Hardware HSM Sync**: Enhanced PKCS#11 monitoring and logging.

## Phase 16: Advanced Security & Compliance

- [x] **MFA Rate Limiting**: Limit brute-force attempts on TOTP and backup codes.
- [ ] **KRL Sync Optimization**: Implement faster revocation propagation to reduce the 5-minute sync window.
- [ ] **PoP & Auth Integration Tests**: Specific integration tests for Proof-of-Possession and renewal flows.
- [ ] **Professional Audit Readiness**: Final sweep of the security model and documentation for external review.

## 🚀 Future Roadmap (Post v1.0.0)

- [ ] **Native Installers (Windows/Mac)**: Create `.msi` or `.pkg` installers for better desktop integration.
- [x] **Credential Auto-Renewal**: Background daemon for Tyr (CLI) to automatically renew certs before expiry.
- [x] **Hardware CA Backend**: Direct PKCS#11 support for the Fenrir server to sign using HSMs.
