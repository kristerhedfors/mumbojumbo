#!/usr/bin/env bash
# Deploy Mumbojumbo DNS Covert Channel Server to Google Cloud Platform
# Automated GCP Compute Engine VM deployment with firewall configuration

set -e  # Exit on error
set -u  # Exit on undefined variable

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Default configuration
PROJECT_ID="${GCP_PROJECT_ID:-}"
ZONE="${GCP_ZONE:-us-central1-a}"
MACHINE_TYPE="${GCP_MACHINE_TYPE:-e2-micro}"
INSTANCE_NAME="${GCP_INSTANCE_NAME:-mumbojumbo-server}"
DOMAIN="${MUMBOJUMBO_DOMAIN:-.asd.qwe}"
IMAGE_FAMILY="debian-12"
IMAGE_PROJECT="debian-cloud"
BOOT_DISK_SIZE="10GB"
NETWORK="default"
SUBNET="default"

# Help message
usage() {
    cat << EOF
Usage: $0 [OPTIONS]

Deploy Mumbojumbo DNS covert channel server to Google Cloud Platform.

OPTIONS:
    -p, --project PROJECT_ID    GCP project ID (required)
    -z, --zone ZONE             GCP zone (default: us-central1-a)
    -m, --machine MACHINE_TYPE  Machine type (default: e2-micro)
    -n, --name INSTANCE_NAME    Instance name (default: mumbojumbo-server)
    -d, --domain DOMAIN         DNS domain for mumbojumbo (default: .asd.qwe)
    -h, --help                  Show this help message

EXAMPLES:
    # Basic deployment
    $0 --project my-project --domain .asd.qwe

    # Custom zone and machine type
    $0 -p my-project -z europe-west1-b -m e2-small -d .mysubdomain.example.com

PREREQUISITES:
    - gcloud CLI installed and authenticated
    - Active GCP project with Compute Engine API enabled
    - Sufficient IAM permissions (compute.instances.create, compute.firewalls.create)

OUTPUT:
    - External IP address of created VM
    - DNS configuration instructions
    - SSH access command

EOF
    exit 1
}

# Parse command line arguments
while [[ $# -gt 0 ]]; do
    case $1 in
        -p|--project)
            PROJECT_ID="$2"
            shift 2
            ;;
        -z|--zone)
            ZONE="$2"
            shift 2
            ;;
        -m|--machine)
            MACHINE_TYPE="$2"
            shift 2
            ;;
        -n|--name)
            INSTANCE_NAME="$2"
            shift 2
            ;;
        -d|--domain)
            DOMAIN="$2"
            shift 2
            ;;
        -h|--help)
            usage
            ;;
        *)
            echo -e "${RED}Unknown option: $1${NC}"
            usage
            ;;
    esac
done

# Validate required parameters
if [[ -z "$PROJECT_ID" ]]; then
    echo -e "${RED}Error: Project ID is required${NC}"
    echo "Set via --project or GCP_PROJECT_ID environment variable"
    exit 1
fi

echo -e "${GREEN}=== Mumbojumbo GCP Deployment ===${NC}"
echo "Project ID: $PROJECT_ID"
echo "Zone: $ZONE"
echo "Machine Type: $MACHINE_TYPE"
echo "Instance Name: $INSTANCE_NAME"
echo "Domain: $DOMAIN"
echo ""

# Set active project
echo -e "${YELLOW}Setting active GCP project...${NC}"
gcloud config set project "$PROJECT_ID"

# Check if instance already exists
if gcloud compute instances describe "$INSTANCE_NAME" --zone="$ZONE" &>/dev/null; then
    echo -e "${RED}Error: Instance '$INSTANCE_NAME' already exists in zone '$ZONE'${NC}"
    echo "Delete it first with: gcloud compute instances delete $INSTANCE_NAME --zone=$ZONE"
    exit 1
fi

# Create firewall rule for UDP 53 (DNS)
FIREWALL_RULE="mumbojumbo-allow-dns"
echo -e "${YELLOW}Creating firewall rule: $FIREWALL_RULE${NC}"
if gcloud compute firewall-rules describe "$FIREWALL_RULE" &>/dev/null; then
    echo "Firewall rule already exists, skipping creation"
else
    gcloud compute firewall-rules create "$FIREWALL_RULE" \
        --project="$PROJECT_ID" \
        --network="$NETWORK" \
        --allow=udp:53 \
        --source-ranges=0.0.0.0/0 \
        --target-tags=mumbojumbo-server \
        --description="Allow inbound DNS (UDP 53) for Mumbojumbo server"
    echo -e "${GREEN}✓ Firewall rule created${NC}"
fi

# Generate mumbojumbo keys
echo -e "${YELLOW}Generating encryption keys...${NC}"
if [[ ! -f "mumbojumbo.py" ]]; then
    echo -e "${RED}Error: mumbojumbo.py not found in current directory${NC}"
    exit 1
fi

KEYS_OUTPUT=$(./mumbojumbo.py --gen-keys)
eval "$KEYS_OUTPUT"
echo -e "${GREEN}✓ Keys generated${NC}"

# Create startup script
STARTUP_SCRIPT=$(cat <<'SCRIPT_END'
#!/bin/bash
# Mumbojumbo server startup script for GCP VM

set -e

echo "=== Mumbojumbo Installation ==="

# Update system
apt-get update
DEBIAN_FRONTEND=noninteractive apt-get upgrade -y

# Install dependencies
DEBIAN_FRONTEND=noninteractive apt-get install -y \
    tshark \
    python3 \
    python3-pip \
    python3-venv \
    git \
    curl \
    wget \
    iproute2

# Create installation directory
mkdir -p /opt/mumbojumbo
cd /opt/mumbojumbo

# Create virtual environment
python3 -m venv venv
source venv/bin/activate

# Install Python dependencies
pip3 install --upgrade pip
pip3 install pynacl

# Download mumbojumbo.py (embedded in startup script below)
cat > mumbojumbo.py << 'MUMBOJUMBO_PY_END'
MUMBOJUMBO_PY_CONTENT_PLACEHOLDER
MUMBOJUMBO_PY_END

chmod +x mumbojumbo.py

# Create environment file with keys
mkdir -p /etc/mumbojumbo
cat > /etc/mumbojumbo/mumbojumbo.env << 'ENV_END'
MUMBOJUMBO_SERVER_KEY=SERVER_KEY_PLACEHOLDER
MUMBOJUMBO_CLIENT_KEY=CLIENT_KEY_PLACEHOLDER
MUMBOJUMBO_DOMAIN=DOMAIN_PLACEHOLDER
ENV_END

chmod 600 /etc/mumbojumbo/mumbojumbo.env

# Create log directory
mkdir -p /var/log/mumbojumbo
chmod 755 /var/log/mumbojumbo

# Install systemd service
cat > /etc/systemd/system/mumbojumbo.service << 'SERVICE_END'
[Unit]
Description=Mumbojumbo DNS Covert Channel Server
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
User=root
Group=root
WorkingDirectory=/opt/mumbojumbo
ExecStart=/opt/mumbojumbo/venv/bin/python3 /opt/mumbojumbo/mumbojumbo.py --daemon --verbose
EnvironmentFile=/etc/mumbojumbo/mumbojumbo.env
AmbientCapabilities=CAP_NET_RAW CAP_NET_ADMIN
NoNewPrivileges=yes
PrivateTmp=yes
ProtectSystem=strict
ProtectHome=yes
ReadWritePaths=/var/log/mumbojumbo /opt/mumbojumbo
Restart=always
RestartSec=10s
StandardOutput=journal
StandardError=journal
SyslogIdentifier=mumbojumbo

[Install]
WantedBy=multi-user.target
SERVICE_END

# Reload systemd and enable service
systemctl daemon-reload
systemctl enable mumbojumbo
systemctl start mumbojumbo

echo "=== Mumbojumbo Installation Complete ==="
echo "Status: $(systemctl is-active mumbojumbo)"
echo "Logs: journalctl -u mumbojumbo -f"

SCRIPT_END
)

# Embed mumbojumbo.py content into startup script
MUMBOJUMBO_PY_CONTENT=$(cat mumbojumbo.py)
STARTUP_SCRIPT="${STARTUP_SCRIPT//MUMBOJUMBO_PY_CONTENT_PLACEHOLDER/$MUMBOJUMBO_PY_CONTENT}"
STARTUP_SCRIPT="${STARTUP_SCRIPT//SERVER_KEY_PLACEHOLDER/$MUMBOJUMBO_SERVER_KEY}"
STARTUP_SCRIPT="${STARTUP_SCRIPT//CLIENT_KEY_PLACEHOLDER/$MUMBOJUMBO_CLIENT_KEY}"
STARTUP_SCRIPT="${STARTUP_SCRIPT//DOMAIN_PLACEHOLDER/$DOMAIN}"

# Create temporary file for startup script
STARTUP_SCRIPT_FILE=$(mktemp)
echo "$STARTUP_SCRIPT" > "$STARTUP_SCRIPT_FILE"

# Create the VM instance
echo -e "${YELLOW}Creating VM instance: $INSTANCE_NAME${NC}"
gcloud compute instances create "$INSTANCE_NAME" \
    --project="$PROJECT_ID" \
    --zone="$ZONE" \
    --machine-type="$MACHINE_TYPE" \
    --image-family="$IMAGE_FAMILY" \
    --image-project="$IMAGE_PROJECT" \
    --boot-disk-size="$BOOT_DISK_SIZE" \
    --boot-disk-type=pd-standard \
    --network="$NETWORK" \
    --subnet="$SUBNET" \
    --tags=mumbojumbo-server \
    --metadata-from-file=startup-script="$STARTUP_SCRIPT_FILE" \
    --scopes=https://www.googleapis.com/auth/logging.write,https://www.googleapis.com/auth/monitoring.write

# Clean up temporary file
rm -f "$STARTUP_SCRIPT_FILE"

echo -e "${GREEN}✓ VM instance created${NC}"

# Wait for instance to get external IP
echo -e "${YELLOW}Waiting for external IP address...${NC}"
sleep 5

# Get external IP
EXTERNAL_IP=$(gcloud compute instances describe "$INSTANCE_NAME" \
    --zone="$ZONE" \
    --format='get(networkInterfaces[0].accessConfigs[0].natIP)')

if [[ -z "$EXTERNAL_IP" ]]; then
    echo -e "${RED}Error: Could not retrieve external IP${NC}"
    exit 1
fi

echo -e "${GREEN}✓ External IP: $EXTERNAL_IP${NC}"

# Save configuration to file
CONFIG_FILE="mumbojumbo-deployment-${INSTANCE_NAME}.txt"
cat > "$CONFIG_FILE" << EOF
=== Mumbojumbo GCP Deployment Configuration ===

Instance Details:
  Name: $INSTANCE_NAME
  Zone: $ZONE
  Machine Type: $MACHINE_TYPE
  External IP: $EXTERNAL_IP

Encryption Keys:
  Server Key: $MUMBOJUMBO_SERVER_KEY
  Client Key: $MUMBOJUMBO_CLIENT_KEY
  Domain: $DOMAIN

DNS Configuration Instructions:
  1. Log into your DNS provider (where $DOMAIN's parent zone is hosted)
  2. Add the following DNS records:

     For domain '$DOMAIN' with server IP '$EXTERNAL_IP':

     NS Record:
       Name: $(echo $DOMAIN | sed 's/^\.//')
       Type: NS
       Value: ns1$(echo $DOMAIN)

     A Record (Glue):
       Name: ns1$(echo $DOMAIN | sed 's/^\.//')
       Type: A
       Value: $EXTERNAL_IP

  3. Wait for DNS propagation (5 minutes to 24 hours)
  4. Test with: dig NS $(echo $DOMAIN | sed 's/^\.//')

SSH Access:
  gcloud compute ssh $INSTANCE_NAME --zone=$ZONE --project=$PROJECT_ID

Service Management:
  # View logs
  gcloud compute ssh $INSTANCE_NAME --zone=$ZONE --command="sudo journalctl -u mumbojumbo -f"

  # Check status
  gcloud compute ssh $INSTANCE_NAME --zone=$ZONE --command="sudo systemctl status mumbojumbo"

  # Restart service
  gcloud compute ssh $INSTANCE_NAME --zone=$ZONE --command="sudo systemctl restart mumbojumbo"

Client Configuration:
  # Use these environment variables on the client side
  export MUMBOJUMBO_CLIENT_KEY=$MUMBOJUMBO_CLIENT_KEY
  export MUMBOJUMBO_DOMAIN=$DOMAIN

  # Send data
  echo "test data" | ./mumbojumbo-client.py

Cleanup:
  # Delete instance
  gcloud compute instances delete $INSTANCE_NAME --zone=$ZONE --project=$PROJECT_ID

  # Delete firewall rule
  gcloud compute firewall-rules delete $FIREWALL_RULE --project=$PROJECT_ID

EOF

echo ""
echo -e "${GREEN}=== Deployment Complete ===${NC}"
echo ""
echo -e "${GREEN}Server IP: $EXTERNAL_IP${NC}"
echo ""
echo -e "${YELLOW}Next Steps:${NC}"
echo "1. Configure DNS records (see instructions below)"
echo "2. Wait for DNS propagation"
echo "3. Test DNS delegation: ./test-dns-delegation.sh $DOMAIN $EXTERNAL_IP"
echo "4. Configure client with keys from $CONFIG_FILE"
echo ""
echo -e "${YELLOW}DNS Configuration:${NC}"
echo "Add these records at your DNS provider:"
echo ""
echo "  NS Record:"
echo "    Name: $(echo $DOMAIN | sed 's/^\.//')"
echo "    Value: ns1$(echo $DOMAIN)"
echo ""
echo "  A Record:"
echo "    Name: ns1$(echo $DOMAIN | sed 's/^\.//')"
echo "    Value: $EXTERNAL_IP"
echo ""
echo -e "${YELLOW}Full configuration saved to: $CONFIG_FILE${NC}"
echo ""
echo -e "${YELLOW}SSH to server:${NC}"
echo "  gcloud compute ssh $INSTANCE_NAME --zone=$ZONE"
echo ""
echo -e "${YELLOW}View logs:${NC}"
echo "  gcloud compute ssh $INSTANCE_NAME --zone=$ZONE --command='sudo journalctl -u mumbojumbo -f'"
echo ""
