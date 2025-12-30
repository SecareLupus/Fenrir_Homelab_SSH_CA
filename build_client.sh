#!/bin/bash
# Cross-platform build script for the Client CLI

set -e

# Darwin (macOS)
echo "Building for macOS (Intel/M1)..."
GOOS=darwin GOARCH=amd64 go build -o bin/ssh-ca-client-darwin-amd64 ./cmd/client
GOOS=darwin GOARCH=arm64 go build -o bin/ssh-ca-client-darwin-arm64 ./cmd/client

# Linux
echo "Building for Linux (x64/ARM)..."
GOOS=linux GOARCH=amd64 go build -o bin/ssh-ca-client-linux-amd64 ./cmd/client
GOOS=linux GOARCH=arm64 go build -o bin/ssh-ca-client-linux-arm64 ./cmd/client

# Windows
echo "Building for Windows..."
GOOS=windows GOARCH=amd64 go build -o bin/ssh-ca-client-windows-amd64.exe ./cmd/client

echo "Done! Binaries are in the bin/ directory."
