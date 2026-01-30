# Fenrir SSH CA - Implementation Todo List (V4.2)

## Phase 22: Advanced Fleet Monitoring & Forensics

- [ ] **Gleipnir Metrics**: Export Prometheus-compatible metrics from agents (Heartbeats, SSH connection counts, system load).
- [ ] **Session Auditing**: Track active SSH sessions in the Fenrir dashboard via `journald` integration.
- [ ] **Anomaly Detection**: Basic alerting engine for suspicious activity (e.g., brute-force cert requests).
- [ ] **Global Search**: Unified search across Hosts, Users, and Audit Logs.

## Phase 23: Project Showcase (GitHub Pages)

- [ ] **Marketing Landing Page**: High-quality landing page featuring Fenrir's capabilities.
- [ ] **Visual Feature Tours**: screenshots/recordings showcasing Fenrir, Tyr, and Gleipnir.
- [ ] **Value Proposition Branding**: Clear messaging for both "Homelab Simple" and "Small Business Powerful".
- [ ] **Interactive Diagram**: Web-optimized architecture and trust flow visualization.

## Phase 24: Mobile Ecosystem (Flutter)

- [ ] **Fleet Health Dashboard**: Real-time status and heartbeats in the mobile app.
- [ ] **Remote Approvals**: Push notifications and UI for approving cert requests on the go.
- [ ] **Mobile Audit Log**: Access to identity-based audit tails on mobile.

## Phase 25: Documentation & API Standardization

- [ ] **OpenAPI Specification**: Fully documented public REST API for scripts and third-party integrations.
- [ ] **Automated CA Rotation**: Streamlined workflow for rotating Intermediate keys via the Root CA.
- [ ] **Security Posture Dashboard**: "Health Check" page for outdated agents or weak policy configurations.

## Phase 26: Open-Source IaC (OpenTofu)

- [ ] **OpenTofu Provider**: Manage host inventory and principal policies as code using the new OpenAPI spec.
