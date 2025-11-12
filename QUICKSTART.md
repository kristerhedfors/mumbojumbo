# Mumbojumbo Quick Start Guide

## What is Mumbojumbo?

Mumbojumbo is a DNS tunnel that sends encrypted data via DNS queries. It uses NaCl public key cryptography (SealedBox) to encrypt messages, fragments them into chunks, and encodes each fragment as a DNS subdomain query.

## Quick Test (Recommended: Environment Variables)

### Terminal 1 - Server
```bash
# 1. Generate keys and export to environment (do this once)
./venv/bin/python3 mumbojumbo.py --gen-keys > ~/.mumbojumbo_env
source ~/.mumbojumbo_env

# 2. Start server (requires sudo for packet capture, uses env vars)
sudo -E ./venv/bin/python3 mumbojumbo.py
```

### Terminal 2 - Client
```bash
# Load the same environment variables
source ~/.mumbojumbo_env

# Send data using Python client (no arguments needed!)
echo "Hello World" | ./clients/python/mumbojumbo-client.py
```

## Alternative: Using Config File

### Terminal 1 - Server
```bash
# Generate config (do this once)
./venv/bin/python3 mumbojumbo.py --gen-conf > mumbojumbo.conf
chmod 600 mumbojumbo.conf

# Start server (requires sudo for packet capture)
sudo ./venv/bin/python3 mumbojumbo.py --config mumbojumbo.conf
```

### Terminal 2 - Client
```bash
# Extract client key from config file comments
# Look for: mumbojumbo_client_key = mj_cli_<64_hex_chars>
# Use that key with any client
echo "Hello" | ./clients/python/mumbojumbo-client.py \
  -k mj_cli_<your_key_here> \
  -d .asd.qwe
```

## HTML Client

I've created `client.html` - a single-page web application that:
- Takes server public key and domain suffix as separate inputs
- Has a textarea for your message
- Encrypts and fragments the message using NaCl
- Generates DNS queries (shows them in browser console)
- Works entirely in the browser with no backend needed

**To use:**
```bash
# 1. Generate config
./venv/bin/python3 mumbojumbo.py --gen-conf > mumbojumbo.conf

# 2. Open client in browser
open client.html   # macOS
xdg-open client.html   # Linux
```

Then:
1. Copy the `server_client_key` value from the config comments and paste into "Server Public Key" field
2. Copy the `domain` value (e.g., `.asd.qwe`) and paste into "Domain Suffix" field
3. Type your message in the textarea
4. Click "Send via DNS"
5. Open browser console (F12) to see the DNS queries that would be sent
6. The first query is automatically copied to your clipboard

## Exact Commands to Run

### Setup (one time)
```bash
# 1. Create virtual environment (if not exists)
python3 -m venv venv

# 2. Install dependencies
./venv/bin/pip install pynacl

# 3. Generate keys and save to environment file
./venv/bin/python3 mumbojumbo.py --gen-keys > ~/.mumbojumbo_env

# 4. Load environment variables
source ~/.mumbojumbo_env

# Alternatively, generate a config file
./venv/bin/python3 mumbojumbo.py --gen-conf > mumbojumbo.conf
chmod 600 mumbojumbo.conf
```

### Running the Server

**Option A - With environment variables (recommended):**
```bash
# Load environment
source ~/.mumbojumbo_env

# Start server (sudo -E preserves environment variables)
sudo -E ./venv/bin/python3 mumbojumbo.py
```

**Option B - With config file:**
```bash
# Start server with config
sudo ./venv/bin/python3 mumbojumbo.py --config mumbojumbo.conf
```

**Option C - With CLI overrides:**
```bash
# Override specific settings
sudo ./venv/bin/python3 mumbojumbo.py \
  -k mj_srv_<64_hex_chars> \
  -d .example.com
```

**Why sudo?** The server uses `tshark` to capture network packets, which requires root privileges.

### Sending Data

**Option A - Python client with env vars:**
```bash
source ~/.mumbojumbo_env
echo "Hello World" | ./clients/python/mumbojumbo-client.py
# (No arguments needed - uses environment variables automatically)
```

**Option B - Go client:**
```bash
# Build first
cd clients/go
go build -o mumbojumbo-client mumbojumbo-client.go

# Use client
echo "Hello" | ./mumbojumbo-client \
  -k mj_cli_<64_hex_chars> \
  -d .example.com
```

**Option C - Node.js client:**
```bash
cd clients/nodejs
npm install
echo "Hello" | ./mumbojumbo-client.js \
  -k mj_cli_<64_hex_chars> \
  -d .example.com
```

**Option D - HTML client:**
```bash
# Open client.html in browser
open client.html
# (paste your mj_cli_ key and domain into the form)
```

## Key Format

Mumbojumbo uses hex-encoded keys with prefixes for easy identification:

- **Server key:** `mj_srv_<64_hex_chars>` - Server's private key (keep secret!)
- **Client key:** `mj_cli_<64_hex_chars>` - Server's public key (safe to share)

Example:
```bash
# Server private key (used by server only, keep secret)
mj_srv_f24d8109d69ffc89c688ffd069715691b8c1c583faeda28dfab9a1a092785d8c

# Client public key (given to all clients, safe to share)
mj_cli_6eaa1b50a62694a695c605b7491eb5cf87f1b210284b52cc5c99b3f3e2176048
```

## Configuration Precedence

The server checks configuration in this order:
1. **CLI arguments** (`-k`, `-d`) - highest priority
2. **Environment variables** (`MUMBOJUMBO_SERVER_KEY`, `MUMBOJUMBO_DOMAIN`)
3. **Config file** (`--config mumbojumbo.conf`) - lowest priority

This allows flexible deployment scenarios.

## Handler Pipeline (Optional)

Mumbojumbo supports multiple output handlers for received packets:

### Available Handlers

1. **stdout** - Print to console (default)
2. **smtp** - Forward via email
3. **file** - Write to log file
4. **execute** - Run external command

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
handlers = stdout  # Comma-separated: stdout, smtp, file, execute
mumbojumbo-server-key = mj_srv_3f552aca453bf2e7160c7bd43e3e7208900f512b46d97216e73d5f880bbacb72
mumbojumbo-client-key = mj_cli_063063395197359dda591317d66d3cb7876cb098ad6908c22116cb02257fb679

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
   - Encrypts message with NaCl public key encryption
   - Fragments into chunks (80 bytes default)
   - Encodes each fragment as base32
   - Creates DNS query: `<base32-fragment>.asd.qwe`

2. **Server Side:**
   - Captures DNS queries with `tshark`
   - Filters for configured domain
   - Decodes base32 and decrypts
   - Reassembles fragments
   - Forwards complete message via SMTP or prints

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
