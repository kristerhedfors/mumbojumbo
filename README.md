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

## License

BSD 2-Clause (see mumbojumbo.py)
