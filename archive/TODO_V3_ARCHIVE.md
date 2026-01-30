# Fenrir SSH CA - Implementation Todo List (V3)

## Phase 18: Tyr Client UX & Material Design 3

- [x] **Material Design 3 Implementation**: Transition from Glassmorphism to M3 aesthetics (System tokens, rounded components, M3 color palettes).
- [x] **Modern Typography**: Implement Google Fonts (e.g., Robot, Inter, or Outfit) using M3 type scales.
- [x] **Micro-animations**: Add smooth M3-style transitions and responsive surface interactions.
- [x] **Dynamic Host Inventory**: Replace static hosts with a dynamic list tracking recent connections.
- [x] **Connection Feedback**: Provide visual "Connecting..." states and launch success/failure notifications.

## Phase 19: Desktop Integration & Native Window

- [x] **Native Window Wrapper**: Move the GUI out of the browser into a dedicated native window (using Wails, Webview, or a lightweight wrapper).
- [x] **Appindicator Attachment**: Attempt to implement a "floating" window behavior attached to the system tray/appindicator.
- [x] **Native Desktop Notifications**: Implement system-level alerts for renewal success or FIDO touch requirements.
- [x] **Enhanced Tray Menu**: Add "Recently Connected" hosts directly to the system tray for one-click access.
- [x] **SSH Config Management**: Automatically manage `~/.ssh/config` to use CA certificates for specific hosts.
- [x] **Global Hotkey**: Implement a customizable hotkey (e.g., `Ctrl+Shift+S`) to toggle the Tyr Quick Launch window.

## Phase 20: Security & Robustness Hardening

- [x] **Sensitive Data Security**: Move API keys from plaintext JSON to system-native keychains (Secret Service/Keychain/DPAPI).
- [x] **Interactive Onboarding**: Implement a guided first-run experience for new users.
- [x] **Real-time Status Updates**: Replace polling with WebSockets or SSE for instant GUI feedback.
- [x] **Component-Based UI Refactor**: Modularize the frontend assets (e.g., using Alpine.js or Vite) to improve maintainability.

## Phase 21: Documentation & CI/CD Hardening

- [x] **GitHub Wiki Migration**: Consolidate all project documentation into a structured Git-based wiki.
- [x] **Tier 3 Deep Dive**: Create comprehensive setup and maintenance guides for air-gapped deployments.
- [x] **Wiki Sync Automation**: Implement automated synchronization between the repo and the GitHub Wiki.
- [x] **CI Stability**: Resolve database locking issues (WAL mode) and fix the Windows MSI installer pipeline.
