# Build stage
FROM golang:1.24-alpine AS builder

WORKDIR /app

# Copy go.mod and go.sum (if it exists)
COPY go.mod go.sum* ./
RUN go mod download

# Copy the rest of the code
COPY . .

# Build the server binary
RUN CGO_ENABLED=0 GOOS=linux go build -o ssh-ca ./cmd/server

# Final stage
FROM alpine:latest

WORKDIR /app

# Install runtime dependencies (sqlite needs nothing for modernc, but we might want ssh tools)
RUN apk add --no-cache ca-certificates openssh-client

# Copy the binary from builder
COPY --from=builder /app/ssh-ca .

# Copy web assets
COPY web/ ./web/

# Expose the default port
EXPOSE 8080

# Run the app
CMD ["./ssh-ca"]
