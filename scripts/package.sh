#!/bin/bash

# Packaging script for SSH CA
# Usage: ./scripts/package.sh

set -e

# Note on CGO: Building the GUI (systray) for Linux/macOS requires native development headers.
# Linux: sudo apt install libayatana-appindicator3-dev
# macOS: Requires native build or specialized cross-compiler.

VERSION="1.0.0"
BIN_DIR="bin"
BUILD_DIR="build"

mkdir -p $BIN_DIR
mkdir -p $BUILD_DIR

echo "Building binaries for v$VERSION..."

# 1. Cross-compile for Linux, Windows, macOS
platforms=("linux/amd64" "linux/arm64" "windows/amd64" "darwin/amd64" "darwin/arm64")

for platform in "${platforms[@]}"; do
    PLATFORM_SPLIT=(${platform//\// })
    GOOS=${PLATFORM_SPLIT[0]}
    GOARCH=${PLATFORM_SPLIT[1]}
    
    OUTPUT_NAME="tyr-$GOOS-$GOARCH"
    if [ $GOOS = "windows" ]; then
        OUTPUT_NAME+='.exe'
    fi

    echo "Building $OUTPUT_NAME..."
    # Build CLI
    GOOS=$GOOS GOARCH=$GOARCH go build -o "$BIN_DIR/$OUTPUT_NAME" ./cmd/client
    
    # Build GUI (might fail on some cross-builds DUE TO CGO, but we'll try)
    GUI_NAME="tyr-gui-$GOOS-$GOARCH"
    if [ $GOOS = "windows" ]; then
        GUI_NAME+='.exe'
    fi
    # Note: systray require CGO for Linux/macOS. 
    # We'll try building with CGO enabled.
    
    CC_OVERRIDE=""
    if [ "$GOOS" = "linux" ] && [ "$GOARCH" = "arm64" ] && command -v aarch64-linux-gnu-gcc >/dev/null; then
        CC_OVERRIDE="CC=aarch64-linux-gnu-gcc"
    elif [ "$GOOS" = "windows" ] && [ "$GOARCH" = "amd64" ] && command -v x86_64-w64-mingw32-gcc >/dev/null; then
        CC_OVERRIDE="CC=x86_64-w64-mingw32-gcc"
    fi

    echo "Building $GUI_NAME (CGO_ENABLED=1)..."
    env $CC_OVERRIDE CGO_ENABLED=1 GOOS=$GOOS GOARCH=$GOARCH go build -o "$BIN_DIR/$GUI_NAME" ./cmd/client-gui || \
        echo "Warning: GUI build failed for $platform. Use deploy/builder.Dockerfile for a full cross-build environment."
done

# 2. Create .deb package for Linux (amd64)
echo "Creating .deb package..."
DEB_ROOT="$BUILD_DIR/deb"
mkdir -p "$DEB_ROOT/usr/local/bin"
mkdir -p "$DEB_ROOT/etc/bash_completion.d"
mkdir -p "$DEB_ROOT/DEBIAN"

cp "$BIN_DIR/tyr-linux-amd64" "$DEB_ROOT/usr/local/bin/tyr"
if [ -f "$BIN_DIR/tyr-gui-linux-amd64" ]; then
    cp "$BIN_DIR/tyr-gui-linux-amd64" "$DEB_ROOT/usr/local/bin/tyr-gui"
fi
cp "scripts/completion.sh" "$DEB_ROOT/etc/bash_completion.d/tyr"

cat > "$DEB_ROOT/DEBIAN/control" <<EOF
Package: homelab-ssh-ca
Version: $VERSION
Section: utils
Priority: optional
Architecture: amd64
Maintainer: Desmond <desmond@example.com>
Description: Homelab SSH CA Client and GUI
 A user-friendly tool for managing SSH certificates and launching authenticated sessions.
EOF

dpkg-deb --root-owner-group --build "$DEB_ROOT" "$BIN_DIR/homelab-ssh-ca_$VERSION_amd64.deb"

echo "Done! Artifacts are in $BIN_DIR"
