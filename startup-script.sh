#!/bin/bash
# Mumbojumbo GCP VM Startup Script
# This script can be used as GCP instance metadata startup-script
# or run manually on any Debian/Ubuntu server

set -e

echo "=== Mumbojumbo Server Installation ==="
echo "Starting installation at $(date)"

# Update system packages
echo "Updating system packages..."
apt-get update
DEBIAN_FRONTEND=noninteractive apt-get upgrade -y

# Install dependencies
echo "Installing dependencies (tshark, python3, etc.)..."
DEBIAN_FRONTEND=noninteractive apt-get install -y \
    tshark \
    python3 \
    python3-pip \
    python3-venv \
    git \
    curl \
    wget \
    iproute2 \
    dnsutils

# Create installation directory
echo "Creating installation directory..."
mkdir -p /opt/mumbojumbo
cd /opt/mumbojumbo

# Create virtual environment
echo "Setting up Python virtual environment..."
python3 -m venv venv
source venv/bin/activate

# Install Python dependencies
echo "Installing Python dependencies..."
pip3 install --upgrade pip
pip3 install pynacl

# Download mumbojumbo.py from repository (or use embedded version)
# If running as standalone, mumbojumbo.py should be in current directory
if [[ -f "/tmp/mumbojumbo.py" ]]; then
    echo "Copying mumbojumbo.py from /tmp..."
    cp /tmp/mumbojumbo.py /opt/mumbojumbo/mumbojumbo.py
elif [[ -f "./mumbojumbo.py" ]]; then
    echo "Using local mumbojumbo.py..."
    cp ./mumbojumbo.py /opt/mumbojumbo/mumbojumbo.py
else
    echo "ERROR: mumbojumbo.py not found!"
    echo "Place mumbojumbo.py in current directory or /tmp/"
    exit 1
fi

chmod +x /opt/mumbojumbo/mumbojumbo.py

# Check for environment variables or prompt for manual configuration
if [[ -n "${MUMBOJUMBO_SERVER_KEY:-}" ]] && [[ -n "${MUMBOJUMBO_DOMAIN:-}" ]]; then
    echo "Creating environment file from variables..."
    mkdir -p /etc/mumbojumbo
    cat > /etc/mumbojumbo/mumbojumbo.env << ENV_END
MUMBOJUMBO_SERVER_KEY=${MUMBOJUMBO_SERVER_KEY}
MUMBOJUMBO_CLIENT_KEY=${MUMBOJUMBO_CLIENT_KEY:-}
MUMBOJUMBO_DOMAIN=${MUMBOJUMBO_DOMAIN}
ENV_END
    chmod 600 /etc/mumbojumbo/mumbojumbo.env
    echo "✓ Configuration file created: /etc/mumbojumbo/mumbojumbo.env"
else
    echo "WARNING: Environment variables not set."
    echo "You must manually configure /etc/mumbojumbo/mumbojumbo.env"
    echo "Or set MUMBOJUMBO_SERVER_KEY and MUMBOJUMBO_DOMAIN before running this script."
    echo ""
    echo "Generate keys with: /opt/mumbojumbo/venv/bin/python3 /opt/mumbojumbo/mumbojumbo.py --gen-keys"
fi

# Create log directory
echo "Creating log directory..."
mkdir -p /var/log/mumbojumbo
chmod 755 /var/log/mumbojumbo

# Install systemd service
echo "Installing systemd service..."
cat > /etc/systemd/system/mumbojumbo.service << 'SERVICE_END'
[Unit]
Description=Mumbojumbo DNS Covert Channel Server
Documentation=https://github.com/yourusername/mumbojumbo
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
User=root
Group=root
WorkingDirectory=/opt/mumbojumbo
ExecStart=/opt/mumbojumbo/venv/bin/python3 /opt/mumbojumbo/mumbojumbo.py --daemon --verbose
EnvironmentFile=-/etc/mumbojumbo/mumbojumbo.env
AmbientCapabilities=CAP_NET_RAW CAP_NET_ADMIN
NoNewPrivileges=yes
PrivateTmp=yes
ProtectSystem=strict
ProtectHome=yes
ReadWritePaths=/var/log/mumbojumbo /opt/mumbojumbo
Restart=always
RestartSec=10s
StartLimitInterval=200
StartLimitBurst=5
StandardOutput=journal
StandardError=journal
SyslogIdentifier=mumbojumbo
MemoryMax=512M
TasksMax=50

[Install]
WantedBy=multi-user.target
SERVICE_END

# Reload systemd
echo "Reloading systemd daemon..."
systemctl daemon-reload

# Enable service (but don't start if config is missing)
systemctl enable mumbojumbo

# Only start if configuration exists
if [[ -f "/etc/mumbojumbo/mumbojumbo.env" ]]; then
    echo "Starting mumbojumbo service..."
    systemctl start mumbojumbo

    # Wait a moment and check status
    sleep 2
    if systemctl is-active --quiet mumbojumbo; then
        echo -e "\n✓ Mumbojumbo service is running!"
        systemctl status mumbojumbo --no-pager
    else
        echo -e "\n✗ Mumbojumbo service failed to start"
        echo "Check logs with: journalctl -u mumbojumbo -n 50"
    fi
else
    echo -e "\n✓ Service installed but not started (configuration needed)"
    echo "Configure /etc/mumbojumbo/mumbojumbo.env then run:"
    echo "  sudo systemctl start mumbojumbo"
fi

echo ""
echo "=== Installation Complete ==="
echo ""
echo "Commands:"
echo "  Start service:   sudo systemctl start mumbojumbo"
echo "  Stop service:    sudo systemctl stop mumbojumbo"
echo "  Restart service: sudo systemctl restart mumbojumbo"
echo "  View status:     sudo systemctl status mumbojumbo"
echo "  View logs:       sudo journalctl -u mumbojumbo -f"
echo "  Health check:    sudo /opt/mumbojumbo/venv/bin/python3 /opt/mumbojumbo/mumbojumbo.py --health-check"
echo ""
echo "Configuration:"
echo "  Environment file: /etc/mumbojumbo/mumbojumbo.env"
echo "  Log directory:    /var/log/mumbojumbo"
echo "  Install path:     /opt/mumbojumbo"
echo ""

if [[ -z "${MUMBOJUMBO_SERVER_KEY:-}" ]]; then
    echo "⚠️  IMPORTANT: Generate keys and configure environment file:"
    echo "  sudo /opt/mumbojumbo/venv/bin/python3 /opt/mumbojumbo/mumbojumbo.py --gen-keys"
    echo "  sudo nano /etc/mumbojumbo/mumbojumbo.env"
    echo "  sudo systemctl start mumbojumbo"
    echo ""
fi

echo "Installation completed at $(date)"
