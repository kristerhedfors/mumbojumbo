# Mumbojumbo Quick Start Guide

## What is Mumbojumbo?

Mumbojumbo is a DNS tunnel that sends encrypted data via DNS queries. It uses NaCl public key cryptography to encrypt messages, fragments them into chunks, and encodes each fragment as a DNS subdomain query.

## Quick Test (2 Terminals)

### Terminal 1 - Server
```bash
# Generate config (do this once)
./venv/bin/python3 mumbojumbo.py --gen-config-skel > config.ini
chmod 600 config.ini

# Start server (requires sudo for packet capture)
sudo ./venv/bin/python3 mumbojumbo.py --config config.ini
```

### Terminal 2 - Client
```bash
# Send test data
./venv/bin/python3 test.py --test-client
```

## HTML Client

I've created `client.html` - a single-page web application that:
- Has a textarea for your message
- Has a "Send via DNS" button
- Encrypts and fragments the message
- Generates DNS queries (shows them in browser console)
- Works entirely in the browser with no backend needed

**To use:**
```bash
# Open in your browser
open client.html   # macOS
xdg-open client.html   # Linux
```

Then:
1. Type your message in the textarea
2. Click "Send via DNS"
3. Open browser console (F12) to see the DNS queries that would be sent
4. The first query is automatically copied to your clipboard

## Exact Commands to Run

### Setup (one time)
```bash
# 1. Create virtual environment (if not exists)
python3 -m venv venv

# 2. Install dependencies
./venv/bin/pip install pynacl

# 3. Generate configuration with keys
./venv/bin/python3 mumbojumbo.py --gen-config-skel > config.ini

# 4. Secure the config file
chmod 600 config.ini

# 5. (Optional) Edit config.ini to customize domain and interface
# Default domain: .xyxyx.xy
# Default interface: eth0
```

### Running the Server
```bash
# Start server (captures DNS packets on eth0)
sudo ./venv/bin/python3 mumbojumbo.py --config config.ini
```

**Why sudo?** The server uses `tshark` to capture network packets, which requires root privileges.

### Sending Data

**Option A - Python test client:**
```bash
# In a different terminal
./venv/bin/python3 test.py --test-client
```

**Option B - HTML client:**
```bash
# Open client.html in browser
open client.html
```

**Option C - Manual DNS queries:**
```bash
# Generate keys first
./venv/bin/python3 mumbojumbo.py --gen-keys

# Then send DNS queries manually (replace with your encoded data)
dig @8.8.8.8 <base32-encoded-encrypted-fragment>.xyxyx.xy
```

## Testing Without Root Access

If you can't run with sudo, use the test mode:

```bash
# Terminal 1: Mock server
./venv/bin/python3 test.py --test-server

# Terminal 2: Test client
./venv/bin/python3 test.py --test-client
```

This runs everything in user space without requiring packet capture.

## SMTP Forwarding (Optional)

To forward received messages via email:

```bash
# 1. Encrypt your SMTP password
./venv/bin/python3 mumbojumbo.py --encrypt
# Enter encryption key: (your master password)
# Enter secret value: (your SMTP password)
# Copy the encrypted output

# 2. Add to config.ini:
[smtp]
server = smtp.gmail.com
port = 587
start-tls
username = your-email@gmail.com
encrypted-password = <paste-encrypted-password-here>
from = your-email@gmail.com
to = recipient@example.com

# 3. Test SMTP
./venv/bin/python3 mumbojumbo.py --config config.ini --test-smtp

# 4. Run server (will now forward to email)
sudo ./venv/bin/python3 mumbojumbo.py --config config.ini
```

## Configuration File Format

```ini
[main]
domain = .xyxyx.xy
network-interface = eth0
client-pubkey = <base64-client-public-key>
server-privkey = <base64-server-private-key>

# Optional SMTP forwarding
[smtp]
server = smtp.gmail.com
port = 587
start-tls
username = user@gmail.com
encrypted-password = <encrypted-base64>
from = user@gmail.com
to = recipient@example.com
```

## How It Works

1. **Client Side:**
   - Encrypts message with NaCl public key encryption
   - Fragments into chunks (80 bytes default)
   - Encodes each fragment as base32
   - Creates DNS query: `<base32-fragment>.xyxyx.xy`

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

# Update config.ini with correct interface
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
./venv/bin/python3 mumbojumbo.py --gen-config-skel

# Encrypt a password/secret
./venv/bin/python3 mumbojumbo.py --encrypt

# Test SMTP settings
./venv/bin/python3 mumbojumbo.py --config config.ini --test-smtp

# Show setup guide
python3 setup_and_run.py
```

## Files Created

- `client.html` - Web-based client interface
- `setup_and_run.py` - Detailed setup instructions
- `QUICKSTART.md` - This file
- `config.ini` - Generated configuration (you create this)
- `mumbojumbo.py` - Server (converted to Python 3)
- `test.py` - Test suite (converted to Python 3)

## Summary of Exact Commands

```bash
# Complete workflow:

# 1. Setup (one time)
./venv/bin/python3 mumbojumbo.py --gen-config-skel > config.ini
chmod 600 config.ini

# 2. Run server
sudo ./venv/bin/python3 mumbojumbo.py --config config.ini

# 3. Run client (different terminal)
./venv/bin/python3 test.py --test-client

# Or use HTML client
open client.html
```

That's it! 🎉
