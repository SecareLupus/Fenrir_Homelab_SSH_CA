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

WORKDIR /app

# Install runtime dependencies
RUN apk add --no-cache ca-certificates openssh-client p11-kit

# Copy the binary from builder
COPY --from=builder /app/fenrir .

# Copy web assets
COPY web/ ./web/

# Expose the default port
EXPOSE 8080

# Run the app
CMD ["./fenrir"]
