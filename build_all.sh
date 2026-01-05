#!/bin/bash
# Comprehensive build script for the entire SSH CA Ecosystem

set -e
mkdir -p bin

echo "--- Building Server & Tools ---"
go build -o bin/ssh-ca ./cmd/server
go build -o bin/ssh-ca-client ./cmd/client
go build -o bin/ssh-ca-agent ./cmd/agent

# Build the GUI Client
echo "--- Building Desktop App (GUI) ---"
go build -o bin/ssh-ca-gui ./cmd/client-gui

echo "--- Building PAM Module ---"
# Requires libpam0g-dev on the system
go build -buildmode=c-shared -o bin/pam_ssh_ca.so ./cmd/pam-ssh-ca

echo ""
echo "--- Cross-Compiling for Fleet (arm64) ---"
GOOS=linux GOARCH=arm64 go build -o bin/ssh-ca-agent-arm64 ./cmd/agent

echo ""
echo "--- Cross-Compiling for Workstations ---"
# Windows
GOOS=windows GOARCH=amd64 go build -o bin/ssh-ca-client-win.exe ./cmd/client
GOOS=windows GOARCH=amd64 go build -o bin/ssh-ca-gui-win.exe ./cmd/client-gui

# MacOS
GOOS=darwin GOARCH=arm64 go build -o bin/ssh-ca-gui-mac-m1 ./cmd/client-gui

echo ""
echo "Done! All binaries are in the /bin directory."
