# Mumbojumbo DNS Covert Channel Server
# Container image for cloud deployment (GCP, AWS, Azure, K8s)

FROM debian:bookworm-slim

# Install dependencies
RUN apt-get update && \
    apt-get install -y --no-install-recommends \
        tshark \
        python3 \
        python3-pip \
        iproute2 \
        iputils-ping \
        && rm -rf /var/lib/apt/lists/*

# Install Python dependencies
RUN pip3 install --no-cache-dir pynacl

# Create application directory
WORKDIR /app

# Copy mumbojumbo server
COPY mumbojumbo.py /app/mumbojumbo.py
RUN chmod +x /app/mumbojumbo.py

# Create directory for logs
RUN mkdir -p /var/log/mumbojumbo && \
    chmod 755 /var/log/mumbojumbo

# Expose DNS port (UDP 53)
# Note: Container must run with hostNetwork: true in K8s to capture traffic
EXPOSE 53/udp

# Health check using built-in health check command
# Note: Health check requires NET_ADMIN capability
HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
    CMD ["/app/mumbojumbo.py", "--health-check"]

# Environment variables for configuration
# These should be set via ConfigMap/Secret in K8s or docker run -e
ENV MUMBOJUMBO_SERVER_KEY=""
ENV MUMBOJUMBO_CLIENT_KEY=""
ENV MUMBOJUMBO_DOMAIN=""

# Run as root (required for packet capture with tshark)
# Security context in K8s must include NET_ADMIN + NET_RAW capabilities
USER root

# Default command: run in daemon mode with verbose logging
# Override with custom config: docker run -v /path/to/config:/etc/mumbojumbo.conf mumbojumbo --config /etc/mumbojumbo.conf
ENTRYPOINT ["/app/mumbojumbo.py"]
CMD ["--daemon", "--verbose"]
