# Mumbojumbo Protocol Specification

## Overview

Encrypted DNS tunneling protocol for key-value transmission. Uses ChaCha20-Poly1305 with **dual-layer encryption** (fragment + message level) and single-label base36 DNS encoding.

**Features:** Single client key with derivation, 40-byte wire format, 63-character DNS labels, dual encryption layers.

**Use Cases:** Educational, authorized security testing, CTF challenges, network research.

**Warning:** Demonstration implementation. Not for production or sensitive data.

---

## Architecture Summary

```
Sender:
  Key-Value → Encrypt (inner ChaCha20) → Fragment (28B chunks)
            → Encrypt each fragment (outer ChaCha20) → MAC → Base36 → DNS Query

Receiver:
  DNS Query → Base36 decode → Verify MAC → Decrypt fragment (outer)
            → Reassemble → Verify integrity → Decrypt message (inner) → Key-Value
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
    enc_key = poly1305_mac(client_key, b'enc') + poly1305_mac(client_key, b'enc2')
    auth_key = poly1305_mac(client_key, b'auth') + poly1305_mac(client_key, b'auth2')
    frag_key = poly1305_mac(client_key, b'frag') + poly1305_mac(client_key, b'frag2')
    return enc_key, auth_key, frag_key  # Each 32 bytes
```

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
├───────────────────────────────────────────────────────────────┤
│              Packet ID (u32, big-endian, UNENCRYPTED)         │ 4B
├───────────────────────────────────────────────────────────────┤
│              Fragment Flags (u32, bitfield, UNENCRYPTED)      │ 4B
│              (first flag, more flag, 30-bit index)            │
├───────────────────────────────────────────────────────────────┤
│              Truncated Poly1305 MAC (4 bytes, UNENCRYPTED)    │ 4B
│              (covers encrypted payload only)                  │
├───────────────────────────────────────────────────────────────┤
│                                                               │
│              ENCRYPTED PAYLOAD (28 bytes)                     │
│              ChaCha20, nonce = packet_id + flags              │
│                                                               │
│              Chunk of inner encrypted message                 │
│                                                               │
└───────────────────────────────────────────────────────────────┘
Total: 40 bytes → Base36 → 63 characters
```

### Packet ID (4 bytes, UNENCRYPTED)

Big-endian u32 (0-4294967295). Identifies which message this fragment belongs to.

**Used as first half of encryption nonce:** Combined with fragment flags to form 8-byte nonce.

### Fragment Flags (4 bytes, UNENCRYPTED)

**IMPORTANT:** Flags are transmitted in plaintext (not encrypted).

Bitfield structure (u32, big-endian):

```python
flags = (is_first << 31) | (has_more << 30) | (index & 0x3FFFFFFF)
```

**Used as second half of encryption nonce:** Combined with packet_id to form 8-byte nonce.

### Fragment MAC (4 bytes, UNENCRYPTED)

Truncated Poly1305 MAC over the **encrypted payload only** (28 bytes):

```python
mac = poly1305_mac(frag_key, encrypted_payload)[:4]
```

**Verified BEFORE decryption** to reject invalid fragments early and prevent amplification attacks.

### Encrypted Payload (28 bytes, ENCRYPTED)

ChaCha20-encrypted with `enc_key` using nonce = `packet_id_bytes + flags_bytes` (8 bytes total).

**Nonce construction:**
```python
packet_id_bytes = struct.pack('!I', packet_id)  # 4 bytes
flags_bytes = struct.pack('!I', flags)          # 4 bytes
nonce = packet_id_bytes + flags_bytes           # 8 bytes total
# Pad to 12 bytes for ChaCha20
nonce_12 = nonce + b'\x00\x00\x00\x00'         # 12 bytes
```

Contains a 28-byte chunk of the inner encrypted message. Last fragment may be zero-padded.

### Fragment Flags Detail (UNENCRYPTED)

```
Bit 31 (MSB):  First Fragment Flag (1 = first, 0 = continuation)
Bit 30:        More Fragments Flag (1 = more coming, 0 = last)
Bits 29-0:     Fragment Index (0 to 1,073,741,823)
```

**Examples:**
- `0x80000000` = First & last (single-fragment message), index 0
- `0xC0000000` = First fragment, more coming, index 0
- `0x40000001` = Continuation, more coming, index 1
- `0x00000002` = Last fragment, index 2

**Security note:** Flags are unencrypted for protocol efficiency. An observer can see fragment count and ordering, but cannot see message content or key-value data.

### Base36 Encoding

40 bytes → 63 characters using `0-9A-Z` (case-insensitive decode).

DNS query: `<63chars>.<domain>`

---

## Layer 2: Message Structure (Inner)

After decrypting and reassembling all fragments for a packet_id:

```
┌──────────┬─────────────┬────────────────────┐
│  8 bytes │   8 bytes   │   Variable         │
│  Nonce   │  Integrity  │  Encrypted KV      │
└──────────┴─────────────┴────────────────────┘
```

### Message Nonce (8 bytes)

Random nonce for inner ChaCha20. Zero-padded to 12 bytes: `nonce || 0x00000000`

### Message Integrity (8 bytes)

Poly1305 MAC over `nonce || encrypted_kv`, truncated to 8 bytes.

**MUST be verified BEFORE inner decryption.**

### Encrypted Key-Value (N bytes)

ChaCha20-encrypted plaintext. Only decrypted after integrity passes.

---

## Layer 3: Plaintext Key-Value

After inner decryption:

```
┌──────────┬──────────┬──────────┐
│  1 byte  │  N bytes │  M bytes │
│ Key Len  │ Key Data │  Value   │
└──────────┴──────────┴──────────┘
```

- **Key Length:** u8 (0-255)
- **Key Data:** N bytes (may be empty if key_len=0)
- **Value Data:** Remaining bytes (must have ≥1 byte)

### Key Usage

Keys enable server-side routing and filtering:

**Empty key (`key_len=0`):**
- Default behavior
- Routed to all handlers in pipeline

**Named keys:**
- `logs:error` - Application logging with category
- `metrics:cpu` - Metric data with type
- `events:user_login` - Event tracking

**Upload protocol (`u://` prefix):**
- `u://path/to/file.txt` - File upload with automatic path extraction
- Server extracts `/path/to/file.txt` from key
- Value contains file data
- Routed to upload handler

**Glob pattern matching:**
- Handlers can filter by key patterns
- `logs:/*` matches `logs:error`, `logs:info`, etc.
- `u://**` matches all upload keys
- See HANDLERS.md for configuration

---

## Sender Algorithm

```python
def send(key, value, client_key, domain):
    # 1. Derive keys
    enc_key, auth_key, frag_key = derive_keys(client_key)

    # 2. Build plaintext
    plaintext = bytes([len(key)]) + key + value

    # 3. Inner encryption (message level)
    nonce_inner = os.urandom(8)
    encrypted_kv = chacha20_encrypt(enc_key, nonce_inner, plaintext)
    integrity = poly1305_mac(auth_key, nonce_inner + encrypted_kv)[:8]
    message = nonce_inner + integrity + encrypted_kv

    # 4. Fragment into 28-byte chunks
    packet_id = random_u32()
    fragments = [message[i:i+28] for i in range(0, len(message), 28)]

    # 5. Build and send packets
    for i, frag_data in enumerate(fragments):
        is_first = (i == 0)
        has_more = (i < len(fragments) - 1)

        # Build flags (UNENCRYPTED)
        flags = (is_first << 31) | (has_more << 30) | i
        flags_bytes = struct.pack('!I', flags)

        # Pad payload to 28 bytes
        payload = frag_data.ljust(28, b'\x00')

        # Fragment-level encryption
        packet_id_bytes = struct.pack('!I', packet_id)
        nonce = packet_id_bytes + flags_bytes  # 8 bytes
        nonce_12 = nonce + b'\x00\x00\x00\x00'  # Pad to 12 bytes for ChaCha20
        encrypted_payload = chacha20_encrypt(enc_key, nonce_12, payload)

        # Compute MAC over encrypted payload (verified before decrypt)
        mac = poly1305_mac(frag_key, encrypted_payload)[:4]

        # Assemble final packet (packet_id + flags + mac + encrypted_payload)
        packet = packet_id_bytes + flags_bytes + mac + encrypted_payload  # 40 bytes

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

    # 3. Parse packet (new format: packet_id + flags + mac + encrypted_payload)
    packet_id_bytes = packet[0:4]
    flags_bytes = packet[4:8]
    mac = packet[8:12]
    encrypted_payload = packet[12:40]

    # 4. Parse flags (UNENCRYPTED)
    flags = struct.unpack('!I', flags_bytes)[0]
    packet_id = struct.unpack('!I', packet_id_bytes)[0]
    is_first = (flags >> 31) & 1
    has_more = (flags >> 30) & 1
    index = flags & 0x3FFFFFFF

    # 5. Verify fragment MAC BEFORE decryption
    computed_mac = poly1305_mac(frag_key, encrypted_payload)[:4]
    if computed_mac != mac:
        raise Error("Fragment MAC failed")

    # 6. Fragment-level decryption
    nonce = packet_id_bytes + flags_bytes  # 8 bytes
    nonce_12 = nonce + b'\x00\x00\x00\x00'  # Pad to 12 bytes
    payload = chacha20_encrypt(enc_key, nonce_12, encrypted_payload)  # decrypt

    # 7. Buffer fragment
    buffer[packet_id][index] = payload

    # 9. Check completion (has_more == 0)
    if not has_more:
        # Reassemble
        message = b''.join(buffer[packet_id])

        # Parse message
        nonce_inner = message[0:8]
        integrity = message[8:16]
        encrypted_kv = message[16:]

        # Verify integrity BEFORE inner decryption
        computed = poly1305_mac(auth_key, nonce_inner + encrypted_kv)[:8]
        if computed != integrity:
            raise SecurityError("Message integrity failed")

        # Inner decryption (message level)
        plaintext = chacha20_encrypt(enc_key, nonce_inner, encrypted_kv)

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
PACKET_ID_SIZE = 4            # u32
FRAGMENT_MAC_SIZE = 4
FRAGMENT_FLAGS_SIZE = 4       # encrypted
FRAGMENT_PAYLOAD_SIZE = 28    # encrypted

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
CHACHA20_NONCE_SIZE = 12
POLY1305_FULL_TAG = 16
```

---

## Security Properties

**Provides:**
- **Confidentiality:** Dual ChaCha20 encryption (fragment payload + message level)
- **Message integrity:** 8-byte Poly1305 MAC verified before inner decrypt
- **Fragment authentication:** 4-byte Poly1305 MAC verified before payload decrypt
- **Replay resistance per fragment:** Packet ID + flags as nonce prevents identical fragments
- **Amplification attack prevention:** MAC verified before decryption

**Does NOT provide:**
- **Metadata confidentiality:** Fragment flags (first, more, index) are transmitted in plaintext
- Long-term replay protection (no timestamps)
- Forward secrecy
- Sender authentication (anyone with the key can send)
- Rate limiting
- Traffic analysis protection (DNS patterns, fragment counts visible)

---

## Example: Single-Fragment Message

```
Message: key="", value=b"HI"

SENDER:
1. Plaintext: [0x00]b"HI" = 3 bytes
2. Inner nonce: 0x0102030405060708 (8 bytes, random)
3. Encrypted KV: chacha20(enc_key, inner_nonce, plaintext) = 3 bytes
4. Integrity: poly1305(auth_key, nonce+encrypted_kv)[:8] = 8 bytes
5. Message: [8B nonce][8B integrity][3B encrypted] = 19 bytes
6. Fragment params: packet_id=0x00001234, index=0, first=1, more=0
7. Flags: 0x80000000 (UNENCRYPTED, 4 bytes)
8. Payload: [19B message][9B zeros] = 28 bytes
9. Packet ID bytes: 0x00001234 (4 bytes)
10. Fragment nonce: packet_id + flags = 8 bytes, padded to 12 bytes
11. Encrypted payload: chacha20(enc_key, frag_nonce, payload) = 28 bytes
12. MAC: poly1305(frag_key, encrypted_payload)[:4] = 4 bytes
13. Packet: [packet_id][flags][mac][encrypted_payload] = 40 bytes
14. Base36: "XYZ...ABC" (63 chars)
15. DNS: XYZ...ABC.example.com

RECEIVER:
1. Base36 decode → 40 bytes
2. Parse: packet_id, flags, mac, encrypted_payload (UNENCRYPTED FLAGS!)
3. Parse flags: first=1, more=0, index=0
4. Verify fragment MAC ✓ (before decrypt)
5. Fragment decrypt: nonce=packet_id+flags (8B→12B padded)
6. Payload decrypted: 19 bytes (strip zero padding)
7. Reassemble: 19 bytes (single fragment, complete)
8. Parse message: nonce, integrity, encrypted_kv
9. Verify message integrity ✓
10. Inner decrypt → [0x00]b"HI"
11. Output: key="", value=b"HI"
```

---

## Overhead Analysis

```
Original: N bytes (1B key_len + key + value)
Message: N + 16 bytes (nonce + integrity + encrypted)
Fragments: ceil((N+16) / 28)
Binary: fragments × 40 bytes
Base36: fragments × 63 chars
DNS: + domain suffix per query
```

**1KB Example:**
- Plaintext: 1024 bytes
- Message: 1040 bytes
- Fragments: 38 (ceil(1040/28))
- Binary: 1520 bytes
- Base36: 2394 chars
- Overhead: ~2.3×

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
