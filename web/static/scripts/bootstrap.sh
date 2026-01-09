#!/bin/bash
# Homelab SSH CA - Idempotent Fleet Bootstrap Script
# This script registers a host with the CA and configures SSHD for CA-based auth.

set -e

# Default Configuration
CA_URL="${CA_URL:-}"
API_KEY="${API_KEY:-}"
BIN_DIR="/usr/local/bin"
AGENT_BIN="$BIN_DIR/ssh-ca-agent"
SSHD_CONFIG="/etc/ssh/sshd_config"
CA_PUB_PATH="/etc/ssh/trusted-user-ca-keys.pem"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
BLUE='\033[0;34m'
NC='\033[0m'

log() { echo -e "${BLUE}[INFO]${NC} $1"; }
success() { echo -e "${GREEN}[SUCCESS]${NC} $1"; }
error() { echo -e "${RED}[ERROR]${NC} $1"; exit 1; }

# check_idempotency: Returns 0 if system is already correctly configured and working
check_idempotency() {
    log "Checking existing configuration..."
    
    # 1. Check if binary exists
    if [ ! -f "$AGENT_BIN" ]; then return 1; fi
    
    # 2. Check if agent is registered and has a valid cert
    # We can use the agent itself to check status if we implement a 'status' command
    # For now, let's check for the existence of a host certificate and its validity
    local host_cert="/etc/ssh/ssh_host_ed25519_key-cert.pub"
    if [ ! -f "$host_cert" ]; then return 1; fi
    
    # Check if cert is still valid (not expired)
    if ! ssh-keygen -Lf "$host_cert" | grep -q "Valid: perpetual" && ! ssh-keygen -Lf "$host_cert" | grep -q "Valid: from .* to .*"; then 
        return 1
    fi
    
    # 3. Check sshd_config
    if ! grep -q "TrustedUserCAKeys $CA_PUB_PATH" "$SSHD_CONFIG"; then return 1; fi
    if ! grep -q "HostCertificate $host_cert" "$SSHD_CONFIG"; then return 1; fi

    return 0
}

# Main Execution
if check_idempotency; then
    success "System is already configured and working. No changes made."
    exit 0
fi

log "System needs configuration. Starting bootstrap..."

# 1. Requirements
if [ -z "$CA_URL" ] || [ -z "$API_KEY" ]; then
    log "Missing CA_URL or API_KEY environment variables."
    read -p "Enter CA URL (e.g. https://ca.local): " CA_URL
    read -p "Enter Host API Key: " API_KEY
fi

# 2. Download Agent
log "Downloading ssh-ca-agent..."
# In a real scenario, we'd fetch the binary for the specific architecture.
# For this demo, we assume the server serves it at /static/bin/ssh-ca-agent
curl -sfL "$CA_URL/static/bin/ssh-ca-agent" -o "$AGENT_BIN" || error "Failed to download agent binary"
chmod +x "$AGENT_BIN"

# 3. Register & Enroll
log "Registering host with CA..."
"$AGENT_BIN" register --url "$CA_URL" --key "$API_KEY" || error "Registration failed"

# 4. Configure SSHD
log "Configuring sshd_config..."
curl -sfL "$CA_URL/api/v1/ca/user" -o "$CA_PUB_PATH" || error "Failed to fetch User CA public key"

# Ensure directives exist
if ! grep -q "TrustedUserCAKeys" "$SSHD_CONFIG"; then
    echo "TrustedUserCAKeys $CA_PUB_PATH" >> "$SSHD_CONFIG"
else
    sed -i "s|#\?TrustedUserCAKeys.*|TrustedUserCAKeys $CA_PUB_PATH|g" "$SSHD_CONFIG"
fi

HOST_CERT="/etc/ssh/ssh_host_ed25519_key-cert.pub"
if ! grep -q "HostCertificate" "$SSHD_CONFIG"; then
    echo "HostCertificate $HOST_CERT" >> "$SSHD_CONFIG"
else
    sed -i "s|#\?HostCertificate.*|HostCertificate $HOST_CERT|g" "$SSHD_CONFIG"
fi

log "Restarting sshd..."
systemctl restart sshd || service sshd restart || error "Failed to restart sshd"

success "Bootstrap complete! Host is now part of the CA fleet."
