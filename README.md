# Mumbojumbo

DNS tunnel with NaCl SealedBox encryption. Sends encrypted messages via DNS queries using anonymous one-way encryption.

## Quick Start

```bash
# 1. Install
python3 -m venv venv
./venv/bin/pip install pynacl

# 2. Generate config
./venv/bin/python3 mumbojumbo.py --gen-conf > mumbojumbo.conf
chmod 600 mumbojumbo.conf

# 3. Run server (requires sudo for packet capture)
sudo ./venv/bin/python3 mumbojumbo.py --config mumbojumbo.conf

# 4. Test (in another terminal)
./venv/bin/python3 test.py --test-client
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

The generated `mumbojumbo.conf` includes the configuration needed for both server and client:

```
#
# !! remember to `chmod 0600` this file !!
#
# for use on client-side:
#   domain = .asd.qwe
#   mumbojumbo_client_key = sdcn50krReeK+tcKyodfWhUEkv5/HEu58e1LsfrXTms=
#

[main]
domain = .asd.qwe
network-interface = en0
mumbojumbo-server-key = OTlWa64XPOvLL23LCyE/9DddoaqTQKBbjrieRlSOHmE=
mumbojumbo-client-key = u6DmkkHUVsVjsFFNuQXlM89k25kueOXeKX4j2uE7cQ8=

[smtp]
server = smtp.gmail.com
port = 587
start-tls
username = user@gmail.com
password = password
from = user@gmail.com
to = recipient@example.com
```

**For clients:** Copy the `domain` and `mumbojumbo_client_key` values from the config comments.

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

## Commands

```bash
# Generate keys
./venv/bin/python3 mumbojumbo.py --gen-keys

# Test SMTP
./venv/bin/python3 mumbojumbo.py --config mumbojumbo.conf --test-smtp

# Run tests
./venv/bin/python3 test.py
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
