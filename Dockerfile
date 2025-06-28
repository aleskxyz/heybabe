# Build stage
FROM golang:1.24-alpine AS builder

# Install git and ca-certificates (needed for go mod download)
RUN apk add --no-cache git ca-certificates

# Set working directory
WORKDIR /app

# Copy go mod files
COPY go.mod go.sum ./

# Download dependencies
RUN go mod download

# Copy source code
COPY . .

# Build the application with explicit Go version
RUN CGO_ENABLED=0 GOOS=linux go build -a -installsuffix cgo -o heybabe -trimpath -ldflags "-s -w -buildid= -checklinkname=0" .

# Final stage - using distroless for better security
FROM gcr.io/distroless/static:nonroot

# Copy binary from builder stage
COPY --from=builder /app/heybabe .

# Set entrypoint for the TLS testing tool
ENTRYPOINT ["./heybabe"] 