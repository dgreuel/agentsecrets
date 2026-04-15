# Multi-stage build for the agentsecrets API server
FROM golang:1.24.0-alpine AS builder

WORKDIR /app

# Install build dependencies
RUN apk add --no-cache git gcc musl-dev

# Copy go mod files
COPY go.mod go.sum ./

# Download dependencies
RUN go mod download

# Copy source code
COPY . .

# Build the binary
RUN CGO_ENABLED=1 GOOS=linux go build -a -installsuffix cgo -o agentsecrets ./cmd/agentsecrets

# Final stage
FROM alpine:latest

WORKDIR /app

# Install runtime dependencies
RUN apk add --no-cache ca-certificates sqlite-libs

# Copy the binary from builder
COPY --from=builder /app/agentsecrets /app/agentsecrets

# Create directory for data storage
RUN mkdir -p /app/data

# Expose the proxy server port
EXPOSE 8765

# Set the entry point
ENTRYPOINT ["/app/agentsecrets"]

# Default command runs the proxy server
CMD ["proxy", "start", "--port", "8765"]
