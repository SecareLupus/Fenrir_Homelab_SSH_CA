#!/bin/bash
# Build script for Debian 12 arm64 fleet

set -e

echo "Building for linux/arm64..."
GOOS=linux GOARCH=arm64 go build -o bin/ssh-ca-agent-arm64 ./cmd/agent

echo "Binary built: bin/ssh-ca-agent-arm64"
echo ""
echo "Deployment steps on Debian target:"
echo "1. scp bin/ssh-ca-agent-arm64 user@host:/usr/local/bin/ssh-ca-agent"
echo "2. scp deploy/ssh-ca-agent.service user@host:/etc/systemd/system/"
echo "3. systemctl enable --now ssh-ca-agent"
echo ""
echo "Ensure /etc/ssh/sshd_config contains:"
echo "  TrustedUserCAKeys /etc/ssh/user_ca.pub"
echo "  RevokedKeys /etc/ssh/revoked.krl"
