# Builder Dockerfile for SSH CA
# This creates an environment with all cross-compilation SDKs for CGO-based GUI builds.

FROM golang:1.24-bookworm

# Install cross-compilers and GUI development headers
RUN apt-get update && apt-get install -y \
    gcc-aarch64-linux-gnu \
    gcc-mingw-w64 \
    pkg-config \
    libayatana-appindicator3-dev \
    libglib2.0-dev \
    libgtk-3-dev \
    && rm -rf /var/lib/apt/lists/*

# Note: macOS cross-compilation (osxcross) is not included here as it requires 
# a proprietary macOS SDK which cannot be legally redistributed.
# Instructions for manual macOS SDK addition are provided in the documentation.

WORKDIR /build
COPY . .

# Default command builds everything using the packaging script
CMD ["./scripts/package.sh"]
