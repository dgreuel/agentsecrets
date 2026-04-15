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

# Build the API server binary
RUN CGO_ENABLED=0 GOOS=linux go build -a -installsuffix cgo -o api-server ./server

# Final stage
FROM alpine:latest

WORKDIR /app

# Install runtime dependencies
RUN apk add --no-cache ca-certificates

# Copy the binary from builder
COPY --from=builder /app/api-server /app/api-server

# Expose the API server port
EXPOSE 8080

# Run the API server
ENTRYPOINT ["/app/api-server"]
