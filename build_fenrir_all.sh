#!/bin/bash
# Comprehensive build script for Fenrir SSH CA Ecosystem (Fenrir, Gleipnir, Tyr)

set -e
mkdir -p bin

VERSION=${1:-"local-dev"}
LDFLAGS="-X 'github.com/SecareLupus/Fenrir/internal/config.Version=$VERSION' -s -w"

echo "--- Building Fenrir (Server) & Tools ---"
go build -ldflags="$LDFLAGS" -o bin/fenrir ./cmd/fenrir
go build -ldflags="$LDFLAGS" -o bin/tyr ./cmd/tyr
go build -ldflags="$LDFLAGS" -o bin/gleipnir ./cmd/gleipnir

# Build the GUI Client
echo "--- Building Tyr Desktop (GUI) ---"
go build -ldflags="$LDFLAGS" -o bin/tyr-gui ./cmd/tyr-gui

echo "--- Building PAM Module ---"
# Requires libpam0g-dev on the system
go build -ldflags="$LDFLAGS" -buildmode=c-shared -o bin/pam_fenrir.so ./cmd/pam-fenrir

echo ""
echo "--- Cross-Compiling Gleipnir for Fleet (arm64) ---"
GOOS=linux GOARCH=arm64 go build -ldflags="$LDFLAGS" -o bin/gleipnir-arm64 ./cmd/gleipnir

echo ""
echo "--- Cross-Compiling Tyr for Workstations ---"
# Windows
GOOS=windows GOARCH=amd64 go build -ldflags="$LDFLAGS" -o bin/tyr-win.exe ./cmd/tyr
GOOS=windows GOARCH=amd64 go build -ldflags="$LDFLAGS" -o bin/tyr-gui-win.exe ./cmd/tyr-gui

# MacOS
GOOS=darwin GOARCH=arm64 go build -ldflags="$LDFLAGS" -o bin/tyr-gui-mac-m1 ./cmd/tyr-gui

echo ""
echo "Done! All binaries are in the /bin directory."
