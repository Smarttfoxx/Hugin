# Hugin Network Scanner - Production Docker Image
# Multi-stage build for optimized production image

# Build stage
FROM ubuntu:22.04 AS builder

# Install build dependencies
RUN apt-get update && apt-get install -y \
    build-essential \
    g++ \
    cmake \
    git \
    libssl-dev \
    liblua5.3-dev \
    libldap2-dev \
    libldns-dev \
    libmicrohttpd-dev \
    pkg-config \
    && rm -rf /var/lib/apt/lists/*

# Set working directory
WORKDIR /build

# Copy source code
COPY . .

# Build Hugin
RUN make clean && make release ENABLE_WEB=1 ENABLE_DISTRIBUTED=1 ENABLE_AUTH=1

# Production stage
FROM ubuntu:22.04

# Install runtime dependencies
RUN apt-get update && apt-get install -y \
    liblua5.3-0 \
    libssl3 \
    libldap-2.5-0 \
    libldns3 \
    libmicrohttpd12 \
    ca-certificates \
    curl \
    && rm -rf /var/lib/apt/lists/*

# Create hugin user and group
RUN groupadd -r hugin && useradd -r -g hugin -d /var/lib/hugin -s /bin/bash hugin

# Create necessary directories
RUN mkdir -p \
    /var/lib/hugin/results \
    /var/log/hugin \
    /etc/hugin \
    /usr/share/hugin \
    && chown -R hugin:hugin /var/lib/hugin /var/log/hugin

# Copy built binary and resources
COPY --from=builder /build/hugin /usr/local/bin/
COPY --from=builder /build/service-probes /usr/share/hugin/
COPY --from=builder /build/wordlists /usr/share/hugin/
COPY --from=builder /build/nmap /usr/share/hugin/
COPY --from=builder /build/web/static /usr/share/hugin/web/static/
COPY --from=builder /build/web/templates /usr/share/hugin/web/templates/
COPY --from=builder /build/config/hugin.conf /etc/hugin/

# Set permissions
RUN chmod +x /usr/local/bin/hugin \
    && chown -R hugin:hugin /usr/share/hugin

# Create configuration for container environment
RUN sed -i 's|/var/log/hugin/hugin.log|/dev/stdout|g' /etc/hugin/hugin.conf \
    && sed -i 's|enable_authentication = true|enable_authentication = false|g' /etc/hugin/hugin.conf \
    && sed -i 's|ssl_enabled = true|ssl_enabled = false|g' /etc/hugin/hugin.conf

# Health check
HEALTHCHECK --interval=30s --timeout=10s --start-period=5s --retries=3 \
    CMD curl -f http://localhost:8080/health || exit 1

# Expose ports
EXPOSE 8080 8443 9090

# Set working directory
WORKDIR /var/lib/hugin

# Switch to hugin user
USER hugin

# Default command
CMD ["/usr/local/bin/hugin", "--config", "/etc/hugin/hugin.conf", "--web-interface"]

# Labels for metadata
LABEL maintainer="Smarttfoxx <contact@smarttfoxx.com>"
LABEL version="2.0"
LABEL description="Hugin Network Scanner - Enterprise Edition"
LABEL org.opencontainers.image.title="Hugin Network Scanner"
LABEL org.opencontainers.image.description="High-performance network scanner with enterprise features"
LABEL org.opencontainers.image.version="2.0"
LABEL org.opencontainers.image.vendor="Smarttfoxx"
LABEL org.opencontainers.image.licenses="GPL-3.0"
LABEL org.opencontainers.image.source="https://github.com/Smarttfoxx/Hugin"
LABEL org.opencontainers.image.documentation="https://github.com/Smarttfoxx/Hugin/wiki"
