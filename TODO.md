# Fenrir SSH CA - Implementation Todo List (V3)

## Phase 18: Tyr Client UX & Material Design 3

- [x] **Material Design 3 Implementation**: Transition from Glassmorphism to M3 aesthetics (System tokens, rounded components, M3 color palettes).
- [x] **Modern Typography**: Implement Google Fonts (e.g., Robot, Inter, or Outfit) using M3 type scales.
- [x] **Micro-animations**: Add smooth M3-style transitions and responsive surface interactions.
- [x] **Dynamic Host Inventory**: Replace static hosts with a dynamic list tracking recent connections.
- [x] **Connection Feedback**: Provide visual "Connecting..." states and launch success/failure notifications.

## Phase 19: Desktop Integration & Native Window

- [ ] **Native Window Wrapper**: Move the GUI out of the browser into a dedicated native window (using Wails, Webview, or a lightweight wrapper).
- [ ] **Appindicator Attachment**: Attempt to implement a "floating" window behavior attached to the system tray/appindicator.
- [ ] **Native Desktop Notifications**: Implement system-level alerts for renewal success or FIDO touch requirements.
- [ ] **Enhanced Tray Menu**: Add "Recently Connected" hosts directly to the system tray for one-click access.
- [ ] **SSH Config Management**: Automatically manage `~/.ssh/config` to use CA certificates for specific hosts.
- [ ] **Global Hotkey**: Implement a customizable hotkey (e.g., `Ctrl+Shift+S`) to toggle the Tyr Quick Launch window.

## Phase 20: Security & Robustness Hardening

- [ ] **Sensitive Data Security**: Move API keys from plaintext JSON to system-native keychains (Secret Service/Keychain/DPAPI).
- [ ] **Interactive Onboarding**: Implement a guided first-run experience for new users.
- [ ] **Real-time Status Updates**: Replace polling with WebSockets or SSE for instant GUI feedback.
- [ ] **Component-Based UI Refactor**: Modularize the frontend assets (e.g., using Alpine.js or Vite) to improve maintainability.
