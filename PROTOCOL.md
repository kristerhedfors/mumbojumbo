# Mumbojumbo Protocol Specification v2.0

## Overview

Mumbojumbo is an encrypted DNS tunneling protocol for transmitting key-value pairs over constrained bandwidth channels. The protocol uses ChaCha20-Poly1305 AEAD encryption with dual-layer authentication: fragment-level MACs for transport validation and message-level integrity checks before decryption.

**Key Features:**
- Single-label DNS encoding (63-character base36)
- Dual-layer authentication (fragment + message integrity)
- Single encryption/decryption (at message level)
- Compact 40-byte wire format
- Support for interleaved multi-packet transmission

**Use Cases:** Educational purposes, authorized security testing, CTF challenges, network research.

**Security Warning:** This is a demonstration implementation. Do not use for production or sensitive data.

---

## Protocol Architecture

```
┌─────────────────────────────────────────────────────────────────────┐
│                         SENDER SIDE                                  │
├─────────────────────────────────────────────────────────────────────┤
│                                                                       │
│  Key-Value Pair: key="file.txt", value=b"Hello World!"              │
│           │                                                           │
│           ▼                                                           │
│  ┌─────────────────────────────────────────────────────────────┐   │
│  │  Layer 4: Build Plaintext Key-Value                         │   │
│  │  [key_length (1B)][key_data][value_data]                    │   │
│  └─────────────────────────────────────────────────────────────┘   │
│           │                                                           │
│           ▼                                                           │
│  ┌─────────────────────────────────────────────────────────────┐   │
│  │  Layer 3: Encrypt Message (ChaCha20, 8-byte nonce)         │   │
│  │  - Generate 8-byte nonce                                     │   │
│  │  - Encrypt plaintext → encrypted_kv                          │   │
│  │  - Compute 8-byte Poly1305 MAC over nonce || encrypted_kv  │   │
│  │  - Build: [nonce (8B)][integrity (8B)][encrypted_kv]       │   │
│  └─────────────────────────────────────────────────────────────┘   │
│           │                                                           │
│           ▼                                                           │
│  ┌─────────────────────────────────────────────────────────────┐   │
│  │  Layer 2: Fragment Message (30-byte chunks)                 │   │
│  │  - Assign Packet ID (u16)                                    │   │
│  │  - Split into 30-byte fragments                              │   │
│  │  - Each fragment: [Packet_ID (2B)][fragment_data (30B)]    │   │
│  └─────────────────────────────────────────────────────────────┘   │
│           │                                                           │
│           ▼                                                           │
│  ┌─────────────────────────────────────────────────────────────┐   │
│  │  Layer 1: Build Transport Packets                           │   │
│  │  - Build 4-byte header (flags + index)                      │   │
│  │  - Compute 4-byte Poly1305 MAC over payload                 │   │
│  │  - Packet: [header][MAC][payload] = 40 bytes               │   │
│  │  - Base36 encode → 63 characters                            │   │
│  │  - DNS name: <63chars>.<domain>                             │   │
│  └─────────────────────────────────────────────────────────────┘   │
│           │                                                           │
│           ▼                                                           │
│  DNS Queries: xy4jq...abc.example.com                               │
│                                                                       │
└───────────────────────────────┬───────────────────────────────────────┘
                                │
                    ┌───────────▼───────────┐
                    │   DNS Infrastructure   │
                    │   Query propagates     │
                    └───────────┬───────────┘
                                │
┌───────────────────────────────▼───────────────────────────────────────┐
│                         RECEIVER SIDE                                  │
├─────────────────────────────────────────────────────────────────────┤
│                                                                       │
│  ┌─────────────────────────────────────────────────────────────┐   │
│  │  Layer 1: Receive & Decode Transport Packets                │   │
│  │  - Capture DNS query (tshark)                                │   │
│  │  - Base36 decode → 40 bytes                                  │   │
│  │  - Parse: [header (4B)][MAC (4B)][payload (32B)]           │   │
│  │  - Verify 4-byte MAC over payload                           │   │
│  │  - Extract flags, index, packet_id, fragment_data           │   │
│  └─────────────────────────────────────────────────────────────┘   │
│           │                                                           │
│           ▼                                                           │
│  ┌─────────────────────────────────────────────────────────────┐   │
│  │  Layer 2: Reassemble Fragments                              │   │
│  │  - Buffer fragments by Packet ID                            │   │
│  │  - Wait until more_flag = 0 (last fragment)                │   │
│  │  - Concatenate all fragment_data in order                   │   │
│  └─────────────────────────────────────────────────────────────┘   │
│           │                                                           │
│           ▼                                                           │
│  ┌─────────────────────────────────────────────────────────────┐   │
│  │  Layer 3: Verify & Decrypt Message                          │   │
│  │  - Parse: [nonce (8B)][integrity (8B)][encrypted_kv]       │   │
│  │  - Verify 8-byte Poly1305 MAC (BEFORE decryption)          │   │
│  │  - If MAC fails: DISCARD, log security event                │   │
│  │  - If MAC passes: Decrypt with ChaCha20                     │   │
│  └─────────────────────────────────────────────────────────────┘   │
│           │                                                           │
│           ▼                                                           │
│  ┌─────────────────────────────────────────────────────────────┐   │
│  │  Layer 4: Extract Key-Value                                 │   │
│  │  - Parse: [key_length][key_data][value_data]                │   │
│  │  - Deliver (key, value) to application                       │   │
│  └─────────────────────────────────────────────────────────────┘   │
│           │                                                           │
│           ▼                                                           │
│  Output: key="file.txt", value=b"Hello World!"                      │
│                                                                       │
└─────────────────────────────────────────────────────────────────────┘
```

---

## Layer 1: Transport Packet (Wire Format)

### Binary Structure (40 bytes)

```
 0                   1                   2                   3
 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
┌───────────────────────────────────────────────────────────────┐
│                                                               │
│                   Fragment Header (u32)                       │
│                   (Network Byte Order)                        │
│                                                               │
├───────────────────────────────────────────────────────────────┤
│                                                               │
│                  Truncated Poly1305 (4 bytes)                │
│                   (First 4 bytes of MAC)                      │
│                                                               │
├───────────────────────────────────────────────────────────────┤
│                                                               │
│                   Fragment Payload (32 bytes)                 │
│                                                               │
│   ┌───────────────────┬──────────────────────────────────┐  │
│   │   Packet ID (u16) │   Fragment Data (30 bytes)       │  │
│   │  (2 bytes, BE)    │                                   │  │
│   └───────────────────┴──────────────────────────────────┘  │
│                                                               │
└───────────────────────────────────────────────────────────────┘

Total Size: 40 bytes binary
Encoded Size: 63 characters (base36)
```

### Fragment Header (4 bytes, u32, big-endian)

Bitfield structure:

```
Bit 31 (MSB):    First Fragment Flag (1 = first, 0 = continuation)
Bit 30:          More Fragments Flag (1 = more coming, 0 = last)
Bits 29-0:       Fragment Index (30-bit unsigned, 0 to 1,073,741,823)
```

**Examples:**
- `0x80000000` = First fragment, no more (single-fragment message), index 0
- `0xC0000000` = First fragment, more coming, index 0
- `0x40000001` = Continuation, more coming, index 1
- `0x00000002` = Last fragment, index 2

**Encoding:**
```python
# Encode
flags = (first_flag << 31) | (more_flag << 30) | (index & 0x3FFFFFFF)
header = flags.to_bytes(4, 'big')

# Decode
flags = int.from_bytes(header, 'big')
first = (flags >> 31) & 1
more = (flags >> 30) & 1
index = flags & 0x3FFFFFFF
```

### Truncated Poly1305 MAC (4 bytes)

- Computed over the 32-byte fragment payload
- Uses first 4 bytes of full 16-byte Poly1305 MAC
- **Purpose:** Fragment-level authentication for transport only
- **NOT** used for message integrity (separate message-level MAC exists)

### Fragment Payload (32 bytes)

```
┌──────────────┬────────────────────────────────┐
│   2 bytes    │         30 bytes               │
│  Packet ID   │      Fragment Data             │
│   (u16, BE)  │       (message chunk)          │
└──────────────┴────────────────────────────────┘
```

**Packet ID (2 bytes):** Identifies which message this fragment belongs to (0-65535)
**Fragment Data (30 bytes):** Chunk of the encrypted message

### Base36 Encoding

Each 40-byte binary packet is encoded to base36:

- **Character set:** `0-9A-Z` (uppercase canonical, case-insensitive decode)
- **Encoding:** Treat 40 bytes as 320-bit big integer, convert to base36
- **Result:** Exactly 63 characters (fits in single DNS label)

```python
# Example
binary_packet = b'\x42' * 40  # 40 bytes
base36_str = base36_encode(binary_packet)  # "6F1O4TZ...MTFPA" (63 chars)
dns_query = f"{base36_str}.example.com"  # Single-label DNS query
```

**DNS Format:**
```
<63-character-base36-string>.<domain>
```

**Important:** Unlike the old protocol, each packet is a **single DNS label**. No multi-label splitting required.

---

## Layer 2: Fragment Payload Structure

Each fragment payload contains:

```
┌──────────────┬────────────────────────────────┐
│   2 bytes    │         30 bytes               │
│  Packet ID   │      Fragment Data             │
│   (u16, BE)  │                                │
└──────────────┴────────────────────────────────┘
```

### Fields

| Field | Size | Type | Description |
|-------|------|------|-------------|
| **Packet ID** | 2 bytes | u16 (big-endian) | Message identifier (0-65535). Allows reassembly of interleaved packets. |
| **Fragment Data** | 30 bytes | bytes | Chunk of the encrypted message. Last fragment may be shorter (no padding). |

### Reassembly

1. Fragments with the same Packet ID belong to the same message
2. Multiple messages can be transmitted simultaneously (interleaved)
3. Use first/more flags to detect message completion
4. Fragments are ordered by index (0, 1, 2, ...)

---

## Layer 3: Reassembled Message (After Fragments Collected)

Once all fragments for a Packet ID are collected and verified:

```
┌──────────────┬─────────────┬──────────────────────────┐
│   8 bytes    │   8 bytes   │   Variable length        │
│    Nonce     │  Poly1305   │   Encrypted Key-Value    │
│              │  Integrity  │                          │
└──────────────┴─────────────┴──────────────────────────┘
```

### Fields

| Field | Size | Description |
|-------|------|-------------|
| **Message Nonce** | 8 bytes | Nonce for ChaCha20 decryption. Zero-padded to 12 bytes: `nonce \|\| 0x00000000` |
| **Message Integrity** | 8 bytes | Poly1305 MAC over `nonce \|\| encrypted_kv` (truncated to 8 bytes). **VERIFIED BEFORE DECRYPTION.** |
| **Encrypted Key-Value** | N bytes | ChaCha20-encrypted plaintext containing key-value data. Only decrypted after integrity verification passes. |

### Critical Security Property

The 8-byte message integrity MAC **MUST** be verified before any decryption:

1. Reassemble all fragments
2. Parse nonce and integrity MAC
3. Compute MAC over `nonce || encrypted_kv`
4. Compare computed MAC with received MAC (first 8 bytes)
5. **If mismatch:** DISCARD message, log security event, DO NOT decrypt
6. **If match:** Proceed to decrypt

This prevents decryption oracle attacks and ensures message integrity.

---

## Layer 4: Final Decrypted Key-Value

After integrity verification and ChaCha20 decryption:

```
┌──────────────┬──────────────┬──────────────┐
│   1 byte     │   N bytes    │   M bytes    │
│  Key Length  │   Key Data   │  Value Data  │
└──────────────┴──────────────┴──────────────┘
```

### Fields

| Field | Size | Type | Description |
|-------|------|------|-------------|
| **Key Length** | 1 byte | u8 | Length of key (0-255 bytes). If 0, key is empty. |
| **Key Data** | N bytes | bytes | The key (e.g., filename). May be zero-length. |
| **Value Data** | M bytes | bytes | The value (e.g., file contents). Must be at least 1 byte. |

---

## Cryptographic Operations

### Fragment-Level Authentication (Transport Only)

**Purpose:** Validate individual fragments during transmission

**Algorithm:** Poly1305
**Input:** 32-byte fragment payload
**Output:** 4-byte truncated MAC (first 4 bytes of full 16-byte Poly1305)
**Key:** Derived from shared secret

**Note:** This MAC only validates transport. It does NOT guarantee message integrity.

### Message-Level Encryption & Integrity (End-to-End)

**Encryption Algorithm:** ChaCha20
**MAC Algorithm:** Poly1305 (8-byte truncated)
**Nonce:** 8 bytes (zero-padded to 12 bytes for ChaCha20)

**Process:**

1. **Sender:**
   ```python
   # Build plaintext
   plaintext = bytes([key_length]) + key_data + value_data

   # Generate 8-byte nonce
   nonce = os.urandom(8)

   # Encrypt with ChaCha20
   encrypted_kv = chacha20_encrypt(shared_key, nonce, plaintext)

   # Compute 8-byte integrity MAC
   integrity = poly1305_mac(auth_key, nonce + encrypted_kv)[:8]

   # Build complete message
   message = nonce + integrity + encrypted_kv
   ```

2. **Receiver:**
   ```python
   # Parse message
   nonce = message[0:8]
   integrity = message[8:16]
   encrypted_kv = message[16:]

   # VERIFY integrity FIRST (before decryption!)
   computed_mac = poly1305_mac(auth_key, nonce + encrypted_kv)[:8]
   if computed_mac != integrity:
       raise SecurityError("Message integrity check failed")

   # Decrypt (only if integrity passed)
   plaintext = chacha20_decrypt(shared_key, nonce, encrypted_kv)

   # Parse key-value
   key_length = plaintext[0]
   key_data = plaintext[1:1+key_length]
   value_data = plaintext[1+key_length:]
   ```

---

## Implementation Requirements

### Sender Algorithm

```
For each key-value pair:
  1. Assign unique Packet_ID (u16, 0-65535, wraps around)

  2. Build plaintext: [key_length][key_data][value_data]

  3. Encrypt ONCE with ChaCha20:
     a. Generate 8-byte message_nonce
     b. encrypted_kv = ChaCha20(key, nonce, plaintext)

  4. Compute 8-byte integrity:
     a. integrity = Poly1305(auth_key, nonce || encrypted_kv)[0:8]

  5. Build complete message:
     a. message = [nonce (8B)][integrity (8B)][encrypted_kv]

  6. Fragment message into 30-byte chunks:
     For each chunk at index i:
       a. Build fragment payload: [Packet_ID (2B)][fragment_data (30B)]
       b. Compute 4-byte fragment MAC = Poly1305(frag_key, payload)[0:4]
       c. Set first_flag = (i == 0 ? 1 : 0)
       d. Set more_flag = (i == last_index ? 0 : 1)
       e. Build header: (first_flag << 31) | (more_flag << 30) | i
       f. Build packet: [header (4B)][MAC (4B)][payload (32B)]
       g. Base36 encode → 63 characters
       h. Transmit as DNS query: <63chars>.<domain>
       i. Increment fragment_index
```

### Receiver Algorithm

```
1. Receive base36 DNS query (single label)

2. Decode base36 → 40 bytes

3. Parse:
   a. header = bytes[0:4]
   b. mac = bytes[4:8]
   c. payload = bytes[8:40]

4. Verify fragment MAC:
   a. computed = Poly1305(frag_key, payload)[0:4]
   b. If computed != mac: DISCARD, log error

5. Parse header:
   a. flags = int.from_bytes(header, 'big')
   b. first_flag = (flags >> 31) & 1
   c. more_flag = (flags >> 30) & 1
   d. index = flags & 0x3FFFFFFF

6. Parse payload:
   a. packet_id = int.from_bytes(payload[0:2], 'big')
   b. fragment_data = payload[2:32]

7. Buffer fragment by packet_id:
   a. If first packet_id: create new buffer
   b. Store fragment_data at index

8. Check if complete (more_flag == 0):
   a. If not complete: wait for more
   b. If complete: proceed to reassembly

9. Reassemble message:
   a. Concatenate all fragment_data in order
   b. Parse: nonce = msg[0:8], integrity = msg[8:16], encrypted = msg[16:]

10. VERIFY message integrity:
    a. computed = Poly1305(auth_key, nonce || encrypted)[0:8]
    b. If computed != integrity: DISCARD, log security event
    c. If valid: proceed to decryption

11. DECRYPT (only if integrity passed):
    a. plaintext = ChaCha20_decrypt(key, nonce, encrypted)

12. Parse decrypted data:
    a. key_length = plaintext[0]
    b. key_data = plaintext[1:1+key_length]
    c. value_data = plaintext[1+key_length:]

13. Deliver (key, value) to application
```

---

## Protocol Constants

```python
# Wire format
BINARY_PACKET_SIZE = 40           # bytes
BASE36_PACKET_SIZE = 63           # characters
FRAGMENT_HEADER_SIZE = 4          # bytes (u32 bitfield)
FRAGMENT_MAC_SIZE = 4             # bytes (truncated Poly1305)
FRAGMENT_PAYLOAD_SIZE = 32        # bytes

# Payload structure
PACKET_ID_SIZE = 2                # bytes (u16)
FRAGMENT_DATA_SIZE = 30           # bytes

# Message structure
MESSAGE_NONCE_SIZE = 8            # bytes
MESSAGE_INTEGRITY_SIZE = 8        # bytes (truncated Poly1305)
KEY_LENGTH_SIZE = 1               # byte

# Bitfield masks
FIRST_FLAG_MASK = 0x80000000
MORE_FLAG_MASK = 0x40000000
INDEX_MASK = 0x3FFFFFFF

# Crypto
CHACHA20_KEY_SIZE = 32            # bytes
CHACHA20_NONCE_SIZE = 8           # bytes (zero-padded to 12)
POLY1305_KEY_SIZE = 32            # bytes
POLY1305_TAG_SIZE = 16            # bytes (full tag)
```

---

## Security Properties

### What This Protocol Provides

✅ **Confidentiality:** ChaCha20 encryption with 256-bit keys
✅ **Message Integrity:** 8-byte Poly1305 MAC verified before decryption
✅ **Fragment Authentication:** 4-byte MAC validates individual packets
✅ **Defense in Depth:** Two-tier authentication (transport + message)
✅ **Decrypt-Once:** Message encrypted once at sender, decrypted once at receiver
✅ **Tamper Detection:** Integrity failures logged, packets discarded

### What This Protocol Does NOT Provide

❌ **Replay Protection:** No timestamps or sequence numbers
❌ **Forward Secrecy:** Compromised keys expose all past messages
❌ **Sender Authentication:** No sender identity verification
❌ **Rate Limiting:** Susceptible to resource exhaustion
❌ **Fragment Timeout:** Incomplete messages held indefinitely
❌ **Traffic Analysis Protection:** DNS patterns reveal communication

---

## Performance Characteristics

### Overhead Analysis

```
Original Message: N bytes

Message Structure:
  ├─ Key length: 1 byte
  ├─ Key data: K bytes
  ├─ Value data: V bytes
  └─ Total plaintext: 1 + K + V = N bytes

Encryption:
  ├─ Nonce: 8 bytes
  ├─ Integrity MAC: 8 bytes
  ├─ Encrypted data: N bytes
  └─ Total message: 16 + N bytes

Fragmentation:
  ├─ Packet ID: 2 bytes per fragment
  ├─ Fragment data: 30 bytes per fragment
  ├─ Number of fragments: ceil((16 + N) / 30)
  └─ Total fragment overhead: ceil((16 + N) / 30) × 2 bytes

Transport:
  ├─ Header: 4 bytes per fragment
  ├─ MAC: 4 bytes per fragment
  ├─ Payload: 32 bytes per fragment
  └─ Total per fragment: 40 bytes

Base36 Encoding:
  ├─ Expansion: 40 bytes → 63 characters
  ├─ Ratio: ~1.575× (63/40)
  └─ Reversible

DNS Overhead:
  ├─ Domain suffix: len(".example.com") bytes
  └─ Separators: 1 byte per label
```

### Example: 1 KB Message

```
Plaintext: 1024 bytes
Message: 1024 + 16 = 1040 bytes (nonce + MAC + encrypted)
Fragments: ceil(1040 / 30) = 35 fragments
Fragment overhead: 35 × (2 + 4 + 4) = 350 bytes
Total binary: 35 × 40 = 1400 bytes
Base36: 35 × 63 = 2205 characters
DNS: 2205 + (35 × len(domain)) characters

Overhead ratio: ~2.2× (before DNS names)
```

---

## Complete Protocol Example

### Single-Fragment Message

```
Message: key="", value=b"HI" (2 bytes)

SENDER:
-------
1. Plaintext: [0x00]b"HI" = 3 bytes

2. Encrypt:
   - Nonce: 0x0102030405060708
   - Encrypted: 0xABCD (example)
   - Integrity: 0x1122334455667788
   - Message: [nonce (8B)][integrity (8B)][encrypted (2B)] = 18 bytes

3. Fragment (only one fragment needed):
   - Packet ID: 0x0001
   - Fragment data: [0x0001][18 bytes] = 20 bytes (padded to 30)
   - Index: 0, first=1, more=0
   - Header: 0x80000000

4. Build packet:
   - Header: 0x80000000 (4B)
   - Payload: [0x0001][18B message][12B zeros] (32B)
   - MAC: 0x4A5B6C7D (4B, example)
   - Total: 40 bytes

5. Base36 encode: "XYZ...ABC" (63 chars)

6. DNS query: XYZ...ABC.example.com

RECEIVER:
---------
1. Capture: XYZ...ABC.example.com
2. Base36 decode: 40 bytes
3. Verify fragment MAC ✓
4. Parse header: first=1, more=0, index=0
5. Parse payload: packet_id=1, data=18 bytes
6. Complete! (more=0)
7. Reassemble: 18 bytes
8. Parse: nonce (8B), integrity (8B), encrypted (2B)
9. Verify integrity MAC ✓
10. Decrypt: [0x00]b"HI"
11. Parse: key_length=0, key="", value=b"HI"
12. Output: key="", value=b"HI"
```

### Multi-Fragment Message

```
Message: key="file.txt", value=b"The quick brown fox" (27 bytes total)

SENDER:
-------
1. Plaintext: [0x08]b"file.txt"b"The quick brown fox" = 28 bytes

2. Encrypt:
   - Message: [nonce (8B)][integrity (8B)][encrypted (28B)] = 44 bytes

3. Fragment:
   - Packet ID: 0x0042
   - Fragment 0: [0x0042][30 bytes of message] = 32 bytes
   - Fragment 1: [0x0042][14 bytes of message] = 16 bytes (last)

4. Fragment 0:
   - first=1, more=1, index=0
   - Header: 0xC0000000
   - Packet: [header][MAC][payload] = 40 bytes
   - DNS: XYZ...001.example.com

5. Fragment 1:
   - first=0, more=0, index=1
   - Header: 0x00000001
   - Packet: [header][MAC][payload] = 40 bytes
   - DNS: ABC...002.example.com

RECEIVER:
---------
1. Receive XYZ...001.example.com → Fragment 0 (first=1, more=1)
2. Receive ABC...002.example.com → Fragment 1 (first=0, more=0)
3. Reassemble: 44 bytes
4. Verify integrity ✓
5. Decrypt: [0x08]b"file.txt"b"The quick brown fox"
6. Parse: key="file.txt", value=b"The quick brown fox"
```

---

## Key Generation

Keys are 32-byte values encoded in hex format with prefixes:

- **Encryption key:** `mj_key_<64_hex_chars>` (ChaCha20)
- **Auth key:** `mj_auth_<64_hex_chars>` (Poly1305)
- **Fragment key:** `mj_frag_<64_hex_chars>` (fragment MACs)

Generate with:

```bash
./mumbojumbo.py --gen-keys
```

Output:
```bash
export MUMBOJUMBO_KEY=mj_key_<64_hex>
export MUMBOJUMBO_AUTH_KEY=mj_auth_<64_hex>
export MUMBOJUMBO_FRAG_KEY=mj_frag_<64_hex>
export MUMBOJUMBO_DOMAIN=.example.com
```

---

## Comparison to Previous Protocol

| Feature | Old (v1.0) | New (v2.0) |
|---------|------------|------------|
| **Encryption** | NaCl SealedBox (X25519 + XSalsa20) | ChaCha20-Poly1305 |
| **Encryption overhead** | 48 bytes per fragment | 16 bytes per message |
| **Fragment header** | 18 bytes (u64 + u32 + u32 + u8 + u8) | 4 bytes (u32 bitfield) |
| **Packet ID** | u64 (8 bytes) | u16 (2 bytes) |
| **Encoding** | Base32 (multi-label DNS) | Base36 (single-label DNS) |
| **Wire format** | Variable | Fixed 40 bytes |
| **Encryption timing** | Per-fragment | Per-message (once) |
| **Authentication** | Per-fragment only | Dual-layer (fragment + message) |
| **Integrity check** | During decryption | Before decryption |
| **DNS labels per fragment** | 1-4 (multi-label) | 1 (single-label) |

---

## Future Enhancements

Potential improvements:

1. **Replay protection:** Add timestamps and sequence numbers
2. **Forward secrecy:** Implement ephemeral key exchange (ECDH)
3. **Fragment timeouts:** Garbage collect incomplete messages after timeout
4. **Rate limiting:** Prevent resource exhaustion attacks
5. **Bidirectional:** Server responses via DNS TXT records
6. **Compression:** Add optional zlib compression layer

---

## References

### Cryptography
- **RFC 7539:** ChaCha20 and Poly1305 for IETF Protocols
- **RFC 8439:** ChaCha20-Poly1305 AEAD

### DNS
- **RFC 1035:** Domain Names - Implementation and Specification
- **DNS Tunneling:** https://en.wikipedia.org/wiki/DNS_tunneling

---

## License

See source code for full license (BSD 2-Clause).

---

## Disclaimer

⚠️ **FOR EDUCATIONAL AND AUTHORIZED TESTING ONLY**

This protocol implementation is provided for educational purposes, authorized security testing, CTF competitions, and research with permission.

**Do not use for:**
- Bypassing security controls without authorization
- Transmitting sensitive data in production
- Violating network usage policies
- Any illegal activities

The authors assume no liability for misuse of this software.

---

*End of Protocol Specification v2.0*
