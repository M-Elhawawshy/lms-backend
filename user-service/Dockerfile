# Start from a minimal Go image
FROM golang:1.24-alpine AS builder

# Set environment for Go build
ENV CGO_ENABLED=0 \
    GOOS=linux \
    GOARCH=amd64

WORKDIR /app

# Copy go.mod and go.sum to download deps early
COPY go.mod go.sum ./
RUN go mod download

# Copy the source code
COPY . .

# Build the binary
RUN go build -o app .

# Final lightweight stage
FROM alpine:latest

# Set working dir
WORKDIR /app

# Copy the built binary
COPY --from=builder /app/app .

# Declare required env vars (for docs and optional defaults)
ENV DATABASE_URL="" \
    HOST_URL="" \
    KAFKA_URL=""

# Expose the app port (optional, for clarity)
EXPOSE 8080

# Run the app
CMD ["./app"]
