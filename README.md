# Mumbojumbo

DNS tunnel with ChaCha20-Poly1305 encryption. Sends encrypted key-value messages via DNS queries using dual-layer authenticated encryption.

## Quick Start

### Option 1: Environment Variables (Recommended)

```bash
# 1. Generate keys and export to environment
python3 mumbojumbo.py --gen-keys > ~/.mumbojumbo_env
source ~/.mumbojumbo_env

# 2. Run server (uses env vars automatically, requires sudo for packet capture)
sudo -E python3 mumbojumbo.py

# 3. Send data from client (uses env vars automatically)
echo "Hello" | python3 clients/python/mumbojumbo_client.py
```

**Note:** No dependencies required - uses Python 3.8+ standard library only!

### Option 2: Config File

```bash
# 1. Generate config file
python3 mumbojumbo.py --gen-conf > mumbojumbo.conf
chmod 600 mumbojumbo.conf

# 2. Run server with config (requires sudo for packet capture)
sudo python3 mumbojumbo.py --config mumbojumbo.conf

# 3. Use client with keys from config file comments
python3 clients/python/mumbojumbo_client.py \
  --client-key mj_cli_<key_from_config> \
  -d .asd.qwe
```

## What It Does

- **Dual-layer encryption:** ChaCha20-Poly1305 at fragment and message levels
- **Key-value protocol:** Send structured key-value pairs with automatic routing
- **Fragment authentication:** MAC verification before decryption (prevents amplification attacks)
- **Encodes as DNS queries:** Base36-encoded fragments in DNS subdomain labels
- **Server-side reassembly:** Captures DNS packets and reassembles complete messages
- **Flexible handlers:** Route data to stdout, SMTP, files, uploads, or custom executables
- **Filtered routing:** Use glob patterns in keys for handler selection (e.g., `logs:/*` → file handler)
- **Upload protocol:** Special `u://` keys for large file transfers with automatic chunking

## Protocol Capacity

- **Maximum packet size:** ~30 GB (30,064,771,072 bytes)
- **Fragment support:** Up to 1 billion fragments per packet (30-bit index)
- **Wire format:** 40 bytes per fragment (12 bytes header + 28 bytes encrypted payload)
- **Fragment payload:** 28 bytes encrypted data per fragment
- **Encoding:** Base36 (40 bytes → 63 characters per DNS label)
- **Practical use:** Supports multi-GB file transfers with upload protocol

## Configuration

### Key Format

Mumbojumbo uses a single 32-byte master key with KDF (Key Derivation Function):

- **Client key:** `mj_cli_<64_hex_chars>` - Master symmetric key (keep secret!)
  - Derives 3 keys using Poly1305-based KDF:
    - `enc_key` (32 bytes) - ChaCha20 encryption key
    - `auth_key` (32 bytes) - Message integrity MAC key
    - `frag_key` (32 bytes) - Fragment authentication MAC key

**Security:** All parties (server and clients) use the same master key. This is a symmetric encryption system, not public key cryptography.

### Environment Variables (Recommended)

Generate and use environment variables:

```bash
# Generate keys as environment variable declarations
./venv/bin/python3 mumbojumbo.py --gen-keys > ~/.mumbojumbo_env

# Example output:
# export MUMBOJUMBO_CLIENT_KEY=mj_cli_<64_hex_chars>  # Master symmetric key (use with -k)
# export MUMBOJUMBO_DOMAIN=.example.com               # Domain for both server and client

# Load into environment
source ~/.mumbojumbo_env

# Run server (uses MUMBOJUMBO_CLIENT_KEY env var automatically)
sudo ./venv/bin/python3 mumbojumbo.py
```

**Configuration Precedence:** CLI args > Environment variables > Config file

**Note:** The server and client share the same master key (`MUMBOJUMBO_CLIENT_KEY`).

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
# Handler pipeline: comma-separated list (stdout, smtp, upload, packetlog, file, execute, filtered)
handlers = stdout
client-key = mj_cli_063063395197359dda591317d66d3cb7876cb098ad6908c22116cb02257fb679

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

- Python 3.8+ (uses standard library only - no external dependencies)
- `tshark` for packet capture (Wireshark command-line tool)
- Root/sudo access for server (required for packet capture)

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
python3 mumbojumbo.py --help

# Generate keys as environment variables (for easy sourcing)
python3 mumbojumbo.py --gen-keys

# Generate config file skeleton
python3 mumbojumbo.py --gen-conf > mumbojumbo.conf

# Run with config file (requires sudo for packet capture)
sudo python3 mumbojumbo.py --config mumbojumbo.conf

# Run with environment variables (requires sudo, -E preserves env vars)
sudo -E python3 mumbojumbo.py

# Override config with CLI arguments
sudo python3 mumbojumbo.py -k mj_cli_<hex> -d .example.com

# Verbose mode (show logs to stderr)
sudo python3 mumbojumbo.py -v

# Test all configured handlers
python3 mumbojumbo.py --test-handlers

# Run unit tests
python3 test.py
```

### Client Examples

See [clients/](clients/) directory for Python, Go, Node.js, Rust, and C implementations.

```bash
# Python client (no dependencies - standard library only)
echo "Hello" | python3 clients/python/mumbojumbo_client.py \
  --client-key mj_cli_<64_hex_chars> \
  -d .example.com

# Or use environment variables
export MUMBOJUMBO_CLIENT_KEY=mj_cli_<64_hex_chars>
export MUMBOJUMBO_DOMAIN=.example.com
echo "Hello" | python3 clients/python/mumbojumbo_client.py

# Go client (requires Go toolchain)
echo "Hello" | ./clients/go/mumbojumbo-client \
  --client-key mj_cli_<64_hex_chars> \
  -d .example.com

# Node.js client (requires npm install)
echo "Hello" | ./clients/nodejs/mumbojumbo-client.js \
  --client-key mj_cli_<64_hex_chars> \
  -d .example.com
```

## Documentation

- [QUICKSTART.md](QUICKSTART.md) - Detailed setup guide
- [PROTOCOL.md](PROTOCOL.md) - Protocol specification
- [HANDLERS.md](HANDLERS.md) - Handler types and configuration
- [clients/python/README.md](clients/python/README.md) - Python client reference
- [clients/python/API.md](clients/python/API.md) - Python client API documentation

## Security Warning

**Educational/testing purposes only.** Not for production use.

Known limitations:
- **Shared symmetric key:** All parties use the same master key (not public key crypto)
- **No sender authentication:** Anyone with the key can send messages
- **No timestamp protection:** Vulnerable to replay attacks
- **No perfect forward secrecy:** Key compromise reveals all past messages
- **No rate limiting:** Server processes all valid packets
- **Fragment MAC truncation:** 4-byte MAC provides ~32 bits of security (acceptable for covert channel but not for general use)

Use only for:
- Education
- Authorized security testing
- CTF challenges
- Research

## Key-Value Protocol

Mumbojumbo uses a structured key-value protocol for automatic routing and filtering:

```bash
# Send simple message (piped from stdin, no key)
echo "Hello World" | python3 clients/python/mumbojumbo_client.py \
  --client-key mj_cli_<hex> -d .example.com

# Send with explicit key-value pair
python3 clients/python/mumbojumbo_client.py \
  --client-key mj_cli_<hex> \
  -d .example.com \
  -k "myapp:event" \
  -v "data"

# Upload file with special u:// protocol (automatic)
python3 clients/python/mumbojumbo_client.py \
  --client-key mj_cli_<hex> \
  -d .example.com \
  -u /path/to/local/app.log
```

**Key features:**
- **Automatic routing:** Keys like `logs:/*` can be routed to specific handlers
- **Pattern matching:** Use glob patterns in handler configs (`key-filter` option)
- **Upload protocol:** Keys starting with `u://` trigger upload handler with path extraction
- **Metadata:** Keys provide context for server-side processing

## Handler Pipeline

Configure multiple handlers to process reassembled packets:

```ini
# In mumbojumbo.conf
handlers = stdout, smtp, filtered

[filtered]
handler = upload
key-filter = u://**

[filtered_logs]
handler = file
key-filter = logs:/*
path = /var/log/app-logs/
```

**Available handlers:**
- `stdout` - Print packet data to stdout (JSON format)
- `smtp` - Email packets to configured recipients
- `upload` - Save uploaded files to disk (extracts path from `u://` keys)
- `packetlog` - Log all packet metadata and data
- `file` - Save packet data to files
- `execute` - Run external command with packet data
- `filtered` - Route packets to specific handlers based on key glob patterns

See [HANDLERS.md](HANDLERS.md) for detailed handler documentation.

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
