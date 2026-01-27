#!/bin/bash
# Cross-platform build script for the Client CLI

set -e

# Darwin (macOS)
echo "Building for macOS (Intel/M1)..."
GOOS=darwin GOARCH=amd64 go build -o bin/tyr-darwin-amd64 ./cmd/tyr
GOOS=darwin GOARCH=arm64 go build -o bin/tyr-darwin-arm64 ./cmd/tyr

# Linux
echo "Building for Linux (x64/ARM)..."
GOOS=linux GOARCH=amd64 go build -o bin/tyr-linux-amd64 ./cmd/tyr
GOOS=linux GOARCH=arm64 go build -o bin/tyr-linux-arm64 ./cmd/tyr

# Windows
echo "Building for Windows..."
GOOS=windows GOARCH=amd64 go build -o bin/tyr-windows-amd64.exe ./cmd/tyr

echo "Done! Binaries are in the bin/ directory."
