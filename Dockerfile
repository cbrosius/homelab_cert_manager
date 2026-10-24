# Stage 1: Build the Go binary
FROM golang:alpine AS builder

WORKDIR /build

# Install ca-certificates
RUN apk add --no-cache ca-certificates

# Copy dependency manifests
COPY go.mod go.sum ./
RUN go mod download

# Copy source code
COPY . .

# Build statically linked binary without debug symbols or symbol tables
RUN CGO_ENABLED=0 GOOS=linux go build -ldflags="-w -s" -o homelab_cert_manager .

# Stage 2: Minimal, secure runtime image
FROM alpine:latest

# Install runtime dependencies and latest security patches
RUN apk --no-cache upgrade && \
    apk --no-cache add ca-certificates tzdata su-exec

WORKDIR /app

# Create unprivileged application user and group (non-root)
RUN addgroup -S -g 10001 appgroup && \
    adduser -S -u 10001 -G appgroup -h /app -s /sbin/nologin appuser

ENV APP_USER=appuser \
    APP_GROUP=appgroup

# Copy executable and assets from builder
COPY --from=builder /build/homelab_cert_manager /app/
COPY --from=builder /build/templates /app/templates
COPY --from=builder /build/static /app/static
COPY entrypoint.sh /app/entrypoint.sh
RUN chmod +x /app/entrypoint.sh

# Ensure data directory exists with correct ownership
RUN mkdir -p /app/data && chown -R appuser:appgroup /app

VOLUME [ "/app/data" ]
EXPOSE 8443

ENTRYPOINT ["/app/entrypoint.sh"]
CMD ["/app/homelab_cert_manager"]
