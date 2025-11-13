# Mumbojumbo

DNS tunnel with NaCl SealedBox encryption. Sends encrypted messages via DNS queries using anonymous one-way encryption.

## Quick Start

### Option 1: Environment Variables (Recommended)

```bash
# 1. Install
python3 -m venv venv
./venv/bin/pip install pynacl

# 2. Generate keys and export to environment
./venv/bin/python3 mumbojumbo.py --gen-keys > ~/.mumbojumbo_env
source ~/.mumbojumbo_env

# 3. Run server (uses env vars automatically)
sudo ./venv/bin/python3 mumbojumbo.py

# 4. Send data from client (uses env vars automatically)
echo "Hello" | ./clients/python/mumbojumbo-client.py
```

### Option 2: Config File

```bash
# 1. Install
python3 -m venv venv
./venv/bin/pip install pynacl

# 2. Generate config file
./venv/bin/python3 mumbojumbo.py --gen-conf > mumbojumbo.conf
chmod 600 mumbojumbo.conf

# 3. Run server with config
sudo ./venv/bin/python3 mumbojumbo.py --config mumbojumbo.conf

# 4. Use client with keys from config file comments
# (See mumbojumbo_client_key in config comments)
```

## What It Does

- Encrypts messages with NaCl SealedBox (anonymous public key cryptography)
- Fragments encrypted data into chunks
- Encodes chunks as DNS subdomain queries
- Server captures DNS packets and reassembles messages
- Optional SMTP forwarding
- Client only needs server's public key (no client keypair required)

## Protocol Capacity

- **Maximum packet size:** ~320 GB (343,597,383,600 bytes)
- **Fragment support:** Up to 4.3 billion fragments per packet
- **Fragment data size:** 80 bytes per fragment
- **Practical use:** Supports multi-GB file transfers

## Configuration

### Key Format

Keys use hex encoding with prefixes for easy identification:
- **Server keys:** `mj_srv_<64_hex_chars>` - Server's private key (keep secret!)
- **Client keys:** `mj_cli_<64_hex_chars>` - Server's public key (safe to share with clients)

### Environment Variables (Recommended)

Generate and use environment variables:

```bash
# Generate keys as environment variable declarations
./venv/bin/python3 mumbojumbo.py --gen-keys > ~/.mumbojumbo_env

# Example output:
# export MUMBOJUMBO_SERVER_KEY=mj_srv_<64_hex_chars>  # Server private key
# export MUMBOJUMBO_CLIENT_KEY=mj_cli_<64_hex_chars>  # Client public key (use with -k)
# export MUMBOJUMBO_DOMAIN=.example.com              # Domain for both server and client

# Load into environment
source ~/.mumbojumbo_env

# Run server (uses env vars automatically)
sudo ./venv/bin/python3 mumbojumbo.py
```

**Configuration Precedence:** CLI args > Environment variables > Config file

### Config File Format

The generated `mumbojumbo.conf` includes configuration for server and clients:

```ini
#
# !! remember to `chmod 0600` this file !!
#
# for use on client-side:
#   domain = .asd.qwe
#   mumbojumbo_client_key = mj_cli_063063395197359dda591317d66d3cb7876cb098ad6908c22116cb02257fb679
#

[main]
domain = .asd.qwe
network-interface = en0
# Handler pipeline: comma-separated list (stdout, smtp, file, execute)
handlers = stdout
mumbojumbo-server-key = mj_srv_3f552aca453bf2e7160c7bd43e3e7208900f512b46d97216e73d5f880bbacb72
mumbojumbo-client-key = mj_cli_063063395197359dda591317d66d3cb7876cb098ad6908c22116cb02257fb679

[smtp]
server = smtp.gmail.com
port = 587
start-tls
username = user@gmail.com
password = password
from = user@gmail.com
to = recipient@example.com

[file]
path = /var/log/mumbojumbo-packets.log
format = hex

[execute]
command = /usr/local/bin/process-packet.sh
timeout = 5
```

**For clients:** Copy the `mumbojumbo_client_key` (mj_cli_ format) and `domain` from config comments.

## Requirements

- Python 3.6+
- `pynacl` library
- `tshark` for packet capture
- Root/sudo access for server

## Install tshark

```bash
# macOS
brew install wireshark

# Ubuntu/Debian
sudo apt-get install tshark
```

## CLI Commands

```bash
# Show help
./venv/bin/python3 mumbojumbo.py --help

# Generate keys as environment variables (for easy sourcing)
./venv/bin/python3 mumbojumbo.py --gen-keys

# Generate config file skeleton
./venv/bin/python3 mumbojumbo.py --gen-conf > mumbojumbo.conf

# Run with config file
sudo ./venv/bin/python3 mumbojumbo.py --config mumbojumbo.conf

# Run with environment variables
sudo ./venv/bin/python3 mumbojumbo.py
# (uses MUMBOJUMBO_SERVER_KEY and MUMBOJUMBO_DOMAIN if set)

# Override config with CLI arguments
sudo ./venv/bin/python3 mumbojumbo.py -k mj_srv_<hex> -d .example.com

# Verbose mode (show logs to stderr)
sudo ./venv/bin/python3 mumbojumbo.py -v

# Test all configured handlers
./venv/bin/python3 mumbojumbo.py --test-handlers

# Run unit tests
./venv/bin/python3 test.py
```

### Client Examples

See [clients/](clients/) directory for Python, Go, Node.js, Rust, and C implementations.

```bash
# Python client
echo "Hello" | ./clients/python/mumbojumbo-client.py \
  -k mj_cli_<64_hex_chars> \
  -d .example.com

# Go client
echo "Hello" | ./clients/go/mumbojumbo-client \
  -k mj_cli_<64_hex_chars> \
  -d .example.com

# Node.js client
echo "Hello" | ./clients/nodejs/mumbojumbo-client.js \
  -k mj_cli_<64_hex_chars> \
  -d .example.com
```

## Documentation

- [QUICKSTART.md](QUICKSTART.md) - Detailed setup guide
- [PROTOCOL.md](PROTOCOL.md) - Protocol specification

## Security Warning

**Educational/testing purposes only.** Not for production use.

Known limitations:
- No sender authentication (anonymous encryption)
- No timestamp protection (replay attacks)
- No perfect forward secrecy
- No rate limiting

Use only for:
- Education
- Authorized security testing
- CTF challenges
- Research

## Cloud Deployment

Mumbojumbo can be deployed to cloud environments for production-ready DNS covert channel operations. The server has been enhanced with daemon mode, health checks, and cloud-aware network interface detection.

### Prerequisites

1. **A domain or subdomain** you control (e.g., `asd.qwe.foo`)
2. **Access to DNS configuration** for the parent domain
3. **Cloud platform account** (GCP, AWS, Azure) or Docker/Kubernetes environment

### DNS Configuration (All Cloud Providers)

To use mumbojumbo, you must **delegate a subdomain** to your server using DNS NS records.

#### Example: Delegating `asd.qwe.foo` to server at `34.123.45.67`

At your DNS provider (Cloudflare, Route53, Google Cloud DNS, etc.), add these records in the **parent zone** (`qwe.foo`):

```
# NS Record - Delegates subdomain to your server
asd.qwe.foo.  IN  NS  ns1.asd.qwe.foo.

# A Record - Glue record for nameserver
ns1.asd.qwe.foo.  IN  A  34.123.45.67
```

**What this does:**
- DNS queries for `*.asd.qwe.foo` are routed to your server at `34.123.45.67`
- Your server captures these queries (doesn't need to respond)
- Works with **any DNS provider** - just add the records manually

**Test delegation:**
```bash
./test-dns-delegation.sh asd.qwe.foo 34.123.45.67
```

### Deployment Option 1: Google Cloud Platform VM (Recommended)

Automated deployment script for GCP Compute Engine:

```bash
# Deploy to GCP with one command
./deploy-gcp-vm.sh \
  --project my-gcp-project \
  --zone us-central1-a \
  --domain .asd.qwe.foo

# Script will:
# - Create VM with static external IP
# - Configure firewall (allow UDP 53)
# - Install dependencies (tshark, python3, pynacl)
# - Generate encryption keys
# - Install systemd service
# - Output DNS configuration instructions
```

**Manual GCP deployment:**

```bash
# 1. Create VM
gcloud compute instances create mumbojumbo-server \
  --project=my-project \
  --zone=us-central1-a \
  --machine-type=e2-micro \
  --image-family=debian-12 \
  --image-project=debian-cloud \
  --tags=mumbojumbo-server

# 2. Create firewall rule
gcloud compute firewall-rules create mumbojumbo-allow-dns \
  --project=my-project \
  --network=default \
  --allow=udp:53 \
  --source-ranges=0.0.0.0/0 \
  --target-tags=mumbojumbo-server

# 3. SSH to server and run installation
gcloud compute ssh mumbojumbo-server --zone=us-central1-a
sudo bash < startup-script.sh

# 4. Configure keys
sudo /opt/mumbojumbo/venv/bin/python3 /opt/mumbojumbo/mumbojumbo.py --gen-keys
sudo nano /etc/mumbojumbo/mumbojumbo.env

# 5. Start service
sudo systemctl start mumbojumbo
```

**Service management:**
```bash
# View logs
sudo journalctl -u mumbojumbo -f

# Check status
sudo systemctl status mumbojumbo

# Restart service
sudo systemctl restart mumbojumbo
```

### Deployment Option 2: Docker

Run mumbojumbo in a Docker container with host networking:

```bash
# 1. Build image
docker build -t mumbojumbo .

# 2. Generate keys
./mumbojumbo.py --gen-keys

# 3. Run container
docker run -d \
  --name mumbojumbo-server \
  --network host \
  --cap-add NET_ADMIN \
  --cap-add NET_RAW \
  -e MUMBOJUMBO_SERVER_KEY=mj_srv_... \
  -e MUMBOJUMBO_CLIENT_KEY=mj_cli_... \
  -e MUMBOJUMBO_DOMAIN=.asd.qwe.foo \
  mumbojumbo:latest \
  --daemon --verbose

# 4. View logs
docker logs -f mumbojumbo-server

# 5. Health check
docker exec mumbojumbo-server /app/mumbojumbo.py --health-check
```

**Using Docker Compose:**

```bash
# 1. Copy env template and configure
cp config/env.example .env
nano .env  # Add your keys and domain

# 2. Start service
docker-compose up -d

# 3. View logs
docker-compose logs -f
```

### Deployment Option 3: Kubernetes (GKE)

Deploy to Google Kubernetes Engine or any Kubernetes cluster:

```bash
# 1. Build and push image to GCR
docker build -t gcr.io/my-project/mumbojumbo:latest .
docker push gcr.io/my-project/mumbojumbo:latest

# 2. Create secret with keys
kubectl create namespace mumbojumbo
kubectl create secret generic mumbojumbo-keys -n mumbojumbo \
  --from-literal=server-key='mj_srv_...' \
  --from-literal=client-key='mj_cli_...' \
  --from-literal=domain='.asd.qwe.foo'

# 3. Deploy
kubectl apply -f k8s-deployment.yaml

# 4. Check status
kubectl get pods -n mumbojumbo
kubectl logs -f -n mumbojumbo deployment/mumbojumbo

# 5. Health check
kubectl exec -n mumbojumbo deployment/mumbojumbo -- \
  /app/mumbojumbo.py --health-check
```

**Important K8s requirements:**
- `hostNetwork: true` - Required to capture DNS traffic
- `NET_ADMIN` + `NET_RAW` capabilities - Required for packet capture
- Run as root - Required for tshark

### Deployment Option 4: AWS EC2

```bash
# 1. Launch EC2 instance (Ubuntu/Debian)
# Instance type: t3.micro or t3.nano
# Security Group: Allow UDP 53 inbound

# 2. SSH to instance
ssh ubuntu@ec2-instance-ip

# 3. Run installation script
sudo bash < startup-script.sh

# 4. Configure (similar to GCP)
sudo nano /etc/mumbojumbo/mumbojumbo.env

# 5. Start service
sudo systemctl start mumbojumbo
```

**AWS DNS Configuration (Route53):**
Add NS and A records in your hosted zone for domain delegation.

### Deployment Option 5: Azure VM

```bash
# 1. Create Azure VM (Ubuntu/Debian)
# VM size: B1s or B1ls
# NSG: Allow UDP 53 inbound

# 2. SSH to VM
ssh azureuser@vm-ip

# 3. Run installation script
sudo bash < startup-script.sh

# 4. Configure
sudo nano /etc/mumbojumbo/mumbojumbo.env

# 5. Start service
sudo systemctl start mumbojumbo
```

### Server Features

**Daemon mode:**
```bash
# Run with daemon mode (handles SIGTERM, SIGINT gracefully)
./mumbojumbo.py --daemon --verbose
```

**Health checks:**
```bash
# Check if server is healthy (for monitoring/K8s probes)
./mumbojumbo.py --health-check
```

**Startup validation:**
- Automatically checks tshark availability
- Validates root permissions
- Auto-detects network interface (cloud-aware)
- Validates domain format
- Checks log file writability

### Architecture Diagram

```
Client → DNS Query (*.asd.qwe.foo)
       ↓
Public DNS Resolver
       ↓
NS lookup (qwe.foo zone) → ns1.asd.qwe.foo (34.123.45.67)
       ↓
UDP 53 to Server IP
       ↓
GCP VM / Docker / K8s (tshark captures packet)
       ↓
mumbojumbo.py processes query
       ↓
Reassembles data → Handlers (stdout, SMTP, file, execute)
```

### Configuration Files

- **`config/mumbojumbo-server.conf.example`** - Annotated server config template
- **`config/env.example`** - Environment variable template
- **`mumbojumbo.service`** - systemd service unit file
- **`Dockerfile`** - Container image definition
- **`k8s-deployment.yaml`** - Kubernetes deployment manifest
- **`docker-compose.yml`** - Docker Compose configuration

### Deployment Scripts

- **`deploy-gcp-vm.sh`** - Automated GCP VM deployment
- **`startup-script.sh`** - Server installation script (any Debian/Ubuntu)
- **`test-dns-delegation.sh`** - Verify DNS delegation is working

### Cost Estimates (Monthly)

- **GCP e2-micro:** ~$7/month (24/7 uptime)
- **AWS t3.micro:** ~$7-10/month
- **Azure B1s:** ~$8-10/month
- **Data transfer:** Minimal (DNS queries are tiny)

### Troubleshooting

**DNS delegation not working:**
```bash
# Test delegation
./test-dns-delegation.sh asd.qwe.foo 34.123.45.67

# Check NS records
dig NS asd.qwe.foo

# Check glue record
dig A ns1.asd.qwe.foo
```

**Server not receiving queries:**
```bash
# Check if service is running
sudo systemctl status mumbojumbo

# Check firewall (allow UDP 53)
sudo iptables -L -n | grep 53

# Test with tcpdump
sudo tcpdump -i any 'udp port 53'

# Check logs
sudo journalctl -u mumbojumbo -f
```

**Permission issues:**
```bash
# Verify running as root
ps aux | grep mumbojumbo

# Check capabilities (systemd)
sudo systemctl show mumbojumbo | grep Cap

# Manual run for debugging
sudo /opt/mumbojumbo/venv/bin/python3 /opt/mumbojumbo/mumbojumbo.py --verbose
```

**Container networking issues:**
```bash
# Verify host network mode
docker inspect mumbojumbo-server | grep NetworkMode

# Check capabilities
docker inspect mumbojumbo-server | grep CapAdd

# Test health check
docker exec mumbojumbo-server /app/mumbojumbo.py --health-check
```

### Security Considerations

- **Firewall:** Only allow UDP 53 (no other ports needed)
- **Key storage:** Use secrets management (K8s Secrets, GCP Secret Manager, etc.)
- **Logging:** Logs may contain sensitive data - secure log files
- **Rate limiting:** Consider DNS-level rate limiting for DoS protection
- **Monitoring:** Monitor for unusual DNS query volumes

### Production Recommendations

1. **Use environment variables** instead of config files (more secure in cloud)
2. **Store keys in secrets manager** (not in code or config)
3. **Monitor logs** via centralized logging (Cloud Logging, CloudWatch, etc.)
4. **Set up alerts** for service failures
5. **Use static IPs** to avoid DNS record updates
6. **Test DNS delegation** before client deployment
7. **Document your keys** securely (password manager)

## License

BSD 2-Clause (see mumbojumbo.py)
