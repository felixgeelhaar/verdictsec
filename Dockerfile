# Build stage
FROM golang:1.24-alpine AS builder

WORKDIR /app

# Install build dependencies
RUN apk add --no-cache git ca-certificates

# Copy go mod files
COPY go.mod go.sum ./
RUN go mod download

# Copy source
COPY . .

# Build binary
ARG VERSION=dev
ARG COMMIT=unknown
ARG BUILD_DATE=unknown

RUN CGO_ENABLED=0 GOOS=linux go build \
    -ldflags="-s -w -X main.version=${VERSION} -X main.commit=${COMMIT} -X main.buildDate=${BUILD_DATE}" \
    -o /verdict ./cmd/verdict

# Runtime stage
FROM alpine:3.20

# Install runtime dependencies for security tools
RUN apk add --no-cache \
    ca-certificates \
    git \
    && rm -rf /var/cache/apk/*

# Create non-root user
RUN adduser -D -u 1000 verdict
USER verdict

WORKDIR /workspace

# Copy binary from builder
COPY --from=builder /verdict /usr/local/bin/verdict

ENTRYPOINT ["verdict"]
CMD ["--help"]
