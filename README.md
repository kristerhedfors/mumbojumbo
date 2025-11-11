# Mumbojumbo

DNS tunnel with NaCl encryption. Sends encrypted messages via DNS queries.

## Quick Start

```bash
# 1. Install
python3 -m venv venv
./venv/bin/pip install pynacl

# 2. Generate config
./venv/bin/python3 mumbojumbo.py --generate-conf > mumbojumbo.conf
chmod 600 mumbojumbo.conf

# 3. Run server (requires sudo for packet capture)
sudo ./venv/bin/python3 mumbojumbo.py --config mumbojumbo.conf

# 4. Test (in another terminal)
./venv/bin/python3 test.py --test-client
```

## What It Does

- Encrypts messages with NaCl public key cryptography
- Fragments encrypted data into chunks
- Encodes chunks as DNS subdomain queries
- Server captures DNS packets and reassembles messages
- Optional SMTP forwarding

## Configuration

The generated `mumbojumbo.conf` includes a **domain-key** for easy client setup:

```
#
# !! remember to `chmod 0600` this file !!
#
# for use on client-side:
#   client_privkey=yCqIMzFFEvtC95gNXjvmvVumUIJDoia7Yq1UzCf/sGs=
#   server_pubkey=sdcn50krReeK+tcKyodfWhUEkv5/HEu58e1LsfrXTms=
#
# OR use single domain-key (combines server_pubkey_urlsafe + domain):
#   domain_key=sdcn50krReeK-tcKyodfWhUEkv5_HEu58e1LsfrXTms.xyxyx.xy
#
# To recreate domain-key manually:
#   sdcn50krReeK-tcKyodfWhUEkv5_HEu58e1LsfrXTms.xyxyx.xy
#

[main]
domain = .xyxyx.xy
network-interface = en0
client-pubkey = u6DmkkHUVsVjsFFNuQXlM89k25kueOXeKX4j2uE7cQ8=
server-privkey = OTlWa64XPOvLL23LCyE/9DddoaqTQKBbjrieRlSOHmE=

[smtp]
server = smtp.gmail.com
port = 587
start-tls
username = user@gmail.com
password = password
from = user@gmail.com
to = recipient@example.com
```

**For clients:** Just copy the `domain_key` value - it contains both the server public key and domain!

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
