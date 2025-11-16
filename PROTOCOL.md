# Mumbojumbo Protocol Specification

## Overview

Encrypted DNS tunneling protocol for key-value transmission. Uses ChaCha20-Poly1305 with dual-layer authentication and single-label base36 DNS encoding.

**Features:** Single client key with derivation, 40-byte wire format, 63-character DNS labels, dual MACs (fragment + message level).

**Use Cases:** Educational, authorized security testing, CTF challenges, network research.

**Warning:** Demonstration implementation. Not for production or sensitive data.

---

## Architecture Summary

```
Sender:
  Key-Value → Encrypt (ChaCha20) → Fragment (30B chunks) → MAC + Encode → DNS Query

Receiver:
  DNS Query → Decode + Verify MAC → Reassemble → Verify Integrity → Decrypt → Key-Value
```

---

## Key Management

### Single Client Key

All cryptographic keys derive from one 32-byte client key:

```
Client Key: mj_cli_<64_hex_chars>
```

### Key Derivation (Poly1305-based)

```python
def derive_keys(client_key):
    """Derive enc, auth, frag keys from client key."""
    enc_key = poly1305_mac(client_key, b'enc') + poly1305_mac(client_key, b'enc2')
    auth_key = poly1305_mac(client_key, b'auth') + poly1305_mac(client_key, b'auth2')
    frag_key = poly1305_mac(client_key, b'frag') + poly1305_mac(client_key, b'frag2')
    return enc_key, auth_key, frag_key  # Each 32 bytes
```

Each derived key concatenates two 16-byte Poly1305 MACs for 32 bytes total.

### Key Generation

```bash
./mumbojumbo.py --gen-keys
# Output:
export MUMBOJUMBO_CLIENT_KEY=mj_cli_<64_hex>
export MUMBOJUMBO_DOMAIN=.example.com
```

### Key Sources (Priority Order)

1. CLI argument: `--client-key mj_cli_...`
2. Config file: `client-key = mj_cli_...`
3. Environment: `MUMBOJUMBO_CLIENT_KEY`

---

## Layer 1: Wire Format (40 bytes)

### Binary Structure

```
 0                   1                   2                   3
 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
├───────────────────────────────────────────────────────────────┤
│              Fragment Header (u32, flags+index)               │ 4B
├───────────────────────────────────────────────────────────────┤
│              Packet ID (u16, big-endian)                      │ 2B
├───────────────────────────────────────────────────────────────┤
│              Truncated Poly1305 MAC (4 bytes)                 │ 4B
├───────────────────────────────────────────────────────────────┤
│                                                               │
│              Fragment Payload (30 bytes)                      │ 30B
│                                                               │
└───────────────────────────────────────────────────────────────┘
Total: 40 bytes → Base36 → 63 characters
```

### Fragment Header (4 bytes)

```
Bit 31 (MSB):  First Fragment Flag (1 = first, 0 = continuation)
Bit 30:        More Fragments Flag (1 = more coming, 0 = last)
Bits 29-0:     Fragment Index (0 to 1,073,741,823)
```

Examples:
- `0x80000000` = First & last fragment (single-fragment message), index 0
- `0xC0000000` = First fragment, more coming, index 0
- `0x40000001` = Continuation, more coming, index 1
- `0x00000002` = Last fragment, index 2

### Packet ID (2 bytes)

Big-endian u16 (0-65535). Identifies which message this fragment belongs to.

### Fragment MAC (4 bytes)

Truncated Poly1305 MAC over **header + payload** (36 bytes total):

```python
mac = poly1305_mac(frag_key, header + payload)[:4]
```

### Fragment Payload (30 bytes)

Chunk of the encrypted message. Last fragment may be shorter (zero-padded).

### Base36 Encoding

40 bytes → 63 characters using `0-9A-Z` (case-insensitive decode).

DNS query: `<63chars>.<domain>`

---

## Layer 2: Message Structure

After reassembling all fragments for a packet_id:

```
┌──────────┬─────────────┬────────────────────┐
│  8 bytes │   8 bytes   │   Variable         │
│  Nonce   │  Integrity  │  Encrypted KV      │
└──────────┴─────────────┴────────────────────┘
```

### Message Nonce (8 bytes)

Random nonce for ChaCha20. Zero-padded to 12 bytes: `nonce || 0x00000000`

### Message Integrity (8 bytes)

Poly1305 MAC over `nonce || encrypted_kv`, truncated to 8 bytes.

**MUST be verified BEFORE decryption.**

### Encrypted Key-Value (N bytes)

ChaCha20-encrypted plaintext. Only decrypted after integrity passes.

---

## Layer 3: Plaintext Key-Value

After decryption:

```
┌──────────┬──────────┬──────────┐
│  1 byte  │  N bytes │  M bytes │
│ Key Len  │ Key Data │  Value   │
└──────────┴──────────┴──────────┘
```

- **Key Length:** u8 (0-255)
- **Key Data:** N bytes (may be empty if key_len=0)
- **Value Data:** Remaining bytes (must have ≥1 byte)

---

## Sender Algorithm

```python
def send(key, value, client_key, domain):
    # 1. Derive keys
    enc_key, auth_key, frag_key = derive_keys(client_key)

    # 2. Build plaintext
    plaintext = bytes([len(key)]) + key + value

    # 3. Encrypt
    nonce = os.urandom(8)
    encrypted = chacha20_encrypt(enc_key, nonce, plaintext)

    # 4. Compute message integrity
    integrity = poly1305_mac(auth_key, nonce + encrypted)[:8]

    # 5. Build complete message
    message = nonce + integrity + encrypted

    # 6. Fragment into 30-byte chunks
    packet_id = random_u16()
    fragments = [message[i:i+30] for i in range(0, len(message), 30)]

    # 7. Build and send packets
    for i, frag_data in enumerate(fragments):
        is_first = (i == 0)
        has_more = (i < len(fragments) - 1)

        # Header: flags + index
        flags = (is_first << 31) | (has_more << 30) | i
        header = struct.pack('!I', flags) + struct.pack('!H', packet_id)

        # Payload: fragment data (zero-padded to 30 bytes)
        payload = frag_data.ljust(30, b'\x00')

        # MAC covers header + payload
        mac = poly1305_mac(frag_key, header + payload)[:4]

        # Assemble packet
        packet = header + mac + payload  # 40 bytes

        # Encode and send
        dns_label = base36_encode(packet)  # 63 chars
        send_dns_query(f"{dns_label}{domain}")
```

---

## Receiver Algorithm

```python
def receive(dns_query, client_key):
    # 1. Derive keys
    enc_key, auth_key, frag_key = derive_keys(client_key)

    # 2. Decode base36
    label = dns_query.split('.')[0]
    packet = base36_decode(label)  # 40 bytes

    # 3. Parse packet
    header = packet[0:6]       # flags+index (4B) + packet_id (2B)
    mac = packet[6:10]         # 4B
    payload = packet[10:40]    # 30B

    # 4. Verify fragment MAC
    computed_mac = poly1305_mac(frag_key, header + payload)[:4]
    if computed_mac != mac:
        raise Error("Fragment MAC failed")

    # 5. Parse header
    flags = struct.unpack('!I', header[0:4])[0]
    packet_id = struct.unpack('!H', header[4:6])[0]
    is_first = (flags >> 31) & 1
    has_more = (flags >> 30) & 1
    index = flags & 0x3FFFFFFF

    # 6. Buffer fragment
    buffer[packet_id][index] = payload

    # 7. Check completion (has_more == 0)
    if not has_more:
        # Reassemble
        message = b''.join(buffer[packet_id])

        # Parse message
        nonce = message[0:8]
        integrity = message[8:16]
        encrypted = message[16:]

        # Verify integrity BEFORE decryption
        computed = poly1305_mac(auth_key, nonce + encrypted)[:8]
        if computed != integrity:
            raise SecurityError("Message integrity failed")

        # Decrypt
        plaintext = chacha20_decrypt(enc_key, nonce, encrypted)

        # Parse key-value
        key_len = plaintext[0]
        key = plaintext[1:1+key_len]
        value = plaintext[1+key_len:]

        return key, value
```

---

## Protocol Constants

```python
# Wire format
BINARY_PACKET_SIZE = 40
BASE36_PACKET_SIZE = 63
FRAGMENT_HEADER_SIZE = 6      # flags+index (4B) + packet_id (2B)
FRAGMENT_MAC_SIZE = 4
FRAGMENT_PAYLOAD_SIZE = 30

# Message structure
MESSAGE_NONCE_SIZE = 8
MESSAGE_INTEGRITY_SIZE = 8
KEY_LENGTH_SIZE = 1

# Bitfield masks
FIRST_FLAG_MASK = 0x80000000
MORE_FLAG_MASK = 0x40000000
INDEX_MASK = 0x3FFFFFFF

# Crypto
KEY_SIZE = 32
CHACHA20_NONCE_SIZE = 8       # Zero-padded to 12
POLY1305_FULL_TAG = 16
```

---

## Security Properties

**Provides:**
- Confidentiality (ChaCha20, 256-bit keys)
- Message integrity (8-byte Poly1305, verified before decrypt)
- Fragment authentication (4-byte Poly1305)
- Single encryption point (encrypt once at sender)

**Does NOT provide:**
- Replay protection
- Forward secrecy
- Sender authentication
- Rate limiting
- Traffic analysis protection

---

## Example: Single-Fragment Message

```
Message: key="", value=b"HI"

SENDER:
1. Plaintext: [0x00]b"HI" = 3 bytes
2. Nonce: 0x0102030405060708
3. Encrypted: 0xABCDEF (3 bytes)
4. Integrity: 0x1122334455667788
5. Message: [8B nonce][8B integrity][3B encrypted] = 19 bytes
6. Fragment: packet_id=0x0001, index=0, first=1, more=0
7. Header: 0x80000000 0x0001 (6 bytes)
8. Payload: [19B message][11B zeros] (30 bytes)
9. MAC: poly1305(frag_key, header+payload)[:4]
10. Packet: [header][mac][payload] = 40 bytes
11. Base36: "XYZ...ABC" (63 chars)
12. DNS: XYZ...ABC.example.com
```

---

## Overhead Analysis

```
Original: N bytes (1B key_len + key + value)
Message: N + 16 bytes (nonce + integrity + encrypted)
Fragments: ceil((N+16) / 30)
Binary: fragments × 40 bytes
Base36: fragments × 63 chars
DNS: + domain suffix per query
```

**1KB Example:**
- Plaintext: 1024 bytes
- Message: 1040 bytes
- Fragments: 35
- Binary: 1400 bytes
- Base36: 2205 chars
- Overhead: ~2.2×

---

## References

- **RFC 7539:** ChaCha20 and Poly1305
- **RFC 8439:** ChaCha20-Poly1305 AEAD
- **RFC 1035:** DNS Specification

---

## Disclaimer

**FOR EDUCATIONAL AND AUTHORIZED TESTING ONLY**

Not for: bypassing security controls, sensitive data, policy violations, illegal activities.

Authors assume no liability for misuse.
