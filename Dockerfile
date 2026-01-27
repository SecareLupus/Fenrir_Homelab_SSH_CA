# Build stage
FROM golang:1.24-alpine AS builder

WORKDIR /app

# Copy go.mod and go.sum (if it exists)
COPY go.mod go.sum* ./
RUN go mod download

# Copy the rest of the code
COPY . .

# Build the server binary (Fenrir)
RUN CGO_ENABLED=0 GOOS=linux go build -o fenrir ./cmd/fenrir

# Final stage
FROM alpine:latest

WORKDIR /app

# Install runtime dependencies
RUN apk add --no-cache ca-certificates openssh-client

# Copy the binary from builder
COPY --from=builder /app/fenrir .

# Copy web assets
COPY web/ ./web/

# Expose the default port
EXPOSE 8080

# Run the app
CMD ["./fenrir"]
