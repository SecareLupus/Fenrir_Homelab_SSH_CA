# SSH CA - Implementation Todo List (V2)

## Phase 6: Core Refinement & Security (Next Steps)
- [x] **Admin Role Refactor**: Replace hardcoded `username == "admin"` checks with database-backed role lookups.
- [x] **Group-Based Access Control**: Implement groups and allow assigning certificates based on group membership.
- [x] **Granular TTL Policies**: Allow different max TTLs per role or user group.
- [x] **API Documentation**: Generate Swagger/OpenAPI specifications for all endpoints.

## Phase 7: Enterprise Integration
- [ ] **OIDC/SSO Support**: Integrate with Authentik, Authelia, GitHub, or Google for Web UI login.
- [ ] **WebAuthn Support**: Direct browser support for hardware keys (YubiKey/TouchID) as a primary or secondary factor.
- [ ] **Audit Log Webhooks**: Send security events (failed logins, revocations) to Slack or Discord.

## Phase 8: Fleet Operations & Monitoring
- [x] **Host Inventory Dashboard**: View all registered hosts, their certificate status, and last sync time.
- [x] **Fleet Bootstrap Script**: A one-liner script to join a new host (install agent, register, configure sshd).
- [x] **Prometheus Metrics**: Export signing activity, error rates, and system health for monitoring.

## Phase 9: Client UX & Distribution
- [ ] **Desktop Client Polish**: Enhance `client-gui` with system tray integration and improved UI.
- [ ] **Native Installers**: Create `.deb`, `.rpm`, and Windows/macOS installers for the client.
- [ ] **Shell Integration**: Auto-completion for CLI and optional shell aliases for cert-aware SSH.

## Phase 10: Quality Assurance
- [ ] **E2E Integration Tests**: Automated tests using Docker to verify the full signing and connection chain.
- [ ] **Security Review**: Deep audit of intermediate key handling and database encryption at rest.
