# Build stage
FROM golang:1.24-alpine AS builder

WORKDIR /app

# Install build deps for CGO + PKCS#11 headers
RUN apk add --no-cache build-base p11-kit-dev

# Copy go.mod and go.sum (if it exists)
COPY go.mod go.sum* ./
RUN go mod download

# Copy the rest of the code
COPY . .

# Build the server binary (Fenrir) with PKCS#11 support by default
RUN CGO_ENABLED=1 GOOS=linux go build -o fenrir ./cmd/fenrir

# Final stage
FROM alpine:latest

# Create a non-root user
RUN addgroup -S fenrir && adduser -S fenrir -G fenrir

WORKDIR /app

# Install runtime dependencies
RUN apk add --no-cache ca-certificates openssh-client p11-kit

# Copy the binary from builder
COPY --from=builder /app/fenrir .

# Copy web assets
COPY web/ ./web/

# Ensure ownership of data directories if they exist or will be created
# Note: In production, these should be volume-mounted with correct permissions.
RUN mkdir -p /app/data && chown -R fenrir:fenrir /app

# Expose the default port
EXPOSE 8080

# Run as non-root user
USER fenrir

# Run the app
CMD ["./fenrir"]
