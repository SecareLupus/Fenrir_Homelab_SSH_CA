#!/bin/bash
# Build script for Debian 12 arm64 fleet

set -e

echo "Building for linux/arm64..."
GOOS=linux GOARCH=arm64 go build -o bin/gleipnir-arm64 ./cmd/agent

echo "Binary built: bin/gleipnir-arm64"
echo ""
echo "Deployment steps on Debian target:"
echo "1. scp bin/gleipnir-arm64 user@host:/usr/local/bin/gleipnir"
echo "2. scp deploy/gleipnir.service user@host:/etc/systemd/system/"
echo "3. systemctl enable --now gleipnir"
echo ""
echo "Ensure /etc/ssh/sshd_config contains:"
echo "  TrustedUserCAKeys /etc/ssh/user_ca.pub"
echo "  RevokedKeys /etc/ssh/revoked.krl"
