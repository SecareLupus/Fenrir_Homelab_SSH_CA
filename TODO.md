# Fenrir SSH CA - Implementation Todo List (V2)

## Phase 6: Core Refinement & Security
- [x] **Admin Role Refactor**: Replace hardcoded `username == "admin"` checks with database-backed role lookups.
- [x] **Group-Based Access Control**: Implement groups and allow assigning certificates based on group membership.
- [x] **Granular TTL Policies**: Allow different max TTLs per role or user group.
- [x] **API Documentation**: Generate Swagger/OpenAPI specifications for all endpoints.

## Phase 7: Enterprise Integration
- [ ] **OIDC/SSO Support**: Integrate with Authentik, Authelia, GitHub, or Google for Web UI login.
- [ ] **WebAuthn Support**: Direct browser support for hardware keys (YubiKey/TouchID) as a primary factor.
- [ ] **Audit Log Webhooks**: Send security events to Slack or Discord.

## Phase 8: Fleet Operations & Monitoring
- [x] **Host Inventory Dashboard**: View all registered hosts and their status.
- [x] **Fleet Bootstrap Script**: A one-liner script to join a new host.
- [x] **Prometheus Metrics**: Export signing activity and metrics.

## Phase 9: Client UX & Distribution
- [x] **Desktop Client Polish**: Enhance `client-gui` with system tray integration.
- [x] **Automated Release Pipeline**: GitHub Actions for multi-platform binaries and Docker.
- [x] **Linux Distribution**: Automated `.deb` package creation.
- [x] **Version Injection**: Compile-time versioning via `ldflags`.
- [ ] **Native Installers (Windows/Mac)**: Create `.msi` or `.pkg` installers.

## Phase 10: Quality Assurance
- [x] **E2E Integration Tests**: Automated tests using Docker.
- [x] **Release Process Documentation**: Formalized steps for tagging and side-loading.
- [x] **Security Review**: Deep audit of intermediate key handling.
