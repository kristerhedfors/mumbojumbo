# Multi-Language Client Implementation Guide

This guide provides exact specifications for implementing mumbojumbo clients in any language.

## Reference Implementation: Python ✅

The Python client ([clients/python/mumbojumbo-client.py](python/mumbojumbo-client.py)) is the **reference implementation**. All other clients MUST follow the same protocol.

---

## Protocol Overview

Mumbojumbo v2.0 uses ChaCha20-Poly1305 symmetric encryption with dual-layer authentication:

- **Single master key:** All parties (server + clients) share one 32-byte key (`mj_cli_*`)
- **Key derivation:** 3 keys derived via Poly1305-based KDF
- **Dual encryption:** Fragment-level + message-level ChaCha20
- **Fragment authentication:** 4-byte MAC verified before decryption
- **Message integrity:** 8-byte MAC verified before inner decryption
- **Wire format:** 40 bytes per fragment
- **Encoding:** Base36 (63 characters per DNS label)

---

## Wire Format (40 bytes)

All fields in **big-endian** (network byte order):

```
Bytes  0-3:   packet_id        (u32, UNENCRYPTED) - Packet identifier
Bytes  4-7:   fragment_flags   (u32, UNENCRYPTED) - first/more flags + index
Bytes  8-11:  fragment_mac     (4B, UNENCRYPTED)  - Poly1305 MAC (truncated)
Bytes 12-39:  encrypted_payload (28B, ENCRYPTED)  - ChaCha20-encrypted data
```

### Fragment Flags Bitfield (u32, big-endian)

```
Bit 31 (MSB):  First Fragment Flag (1 = first, 0 = continuation)
Bit 30:        More Fragments Flag (1 = more coming, 0 = last)
Bits 29-0:     Fragment Index (0 to 1,073,741,823)
```

**Examples:**
- `0x80000000` = First & last (single fragment), index 0
- `0xC0000000` = First fragment, more coming, index 0
- `0x40000001` = Continuation, more coming, index 1
- `0x00000002` = Last fragment, index 2

---

## Key Management

### Key Format

```
mj_cli_<64_hex_chars>

Example:
mj_cli_6eaa1b50a62694a695c605b7491eb5cf87f1b210284b52cc5c99b3f3e2176048
```

### Key Derivation (Poly1305-based KDF)

From the 32-byte master key, derive three 32-byte keys:

```python
def derive_keys(client_key):
    # Each derived key is two 16-byte Poly1305 MACs concatenated
    enc_key = poly1305(client_key, b'enc') + poly1305(client_key, b'enc2')
    auth_key = poly1305(client_key, b'auth') + poly1305(client_key, b'auth2')
    frag_key = poly1305(client_key, b'frag') + poly1305(client_key, b'frag2')
    return enc_key, auth_key, frag_key  # Each 32 bytes
```

**Libraries:**
- Python: Use built-in Poly1305 (available in Python 3.10+ or implement manually)
- Node.js: `tweetnacl` (Poly1305 available via `crypto_onetimeauth`)
- Go: `golang.org/x/crypto/poly1305`
- Rust: `poly1305` crate
- C: `libsodium` (`crypto_onetimeauth_poly1305`)

---

## Encryption Protocol

### Message Structure (Before Fragmentation)

1. **Build plaintext:**
   ```
   [1 byte: key_length][N bytes: key][M bytes: value]
   ```

2. **Inner encryption (message level):**
   ```python
   nonce_inner = os.urandom(8)  # 8-byte random nonce
   encrypted_kv = chacha20_encrypt(enc_key, nonce_inner, plaintext)
   integrity_mac = poly1305(auth_key, nonce_inner + encrypted_kv)[:8]
   message = nonce_inner + integrity_mac + encrypted_kv
   ```

3. **Fragment into 28-byte chunks:**
   ```python
   fragments = [message[i:i+28] for i in range(0, len(message), 28)]
   ```

### Fragment Wire Format

For each 28-byte fragment chunk:

```python
# Build flags
flags = (is_first << 31) | (has_more << 30) | fragment_index
flags_bytes = struct.pack('!I', flags)

# Pad payload to 28 bytes
payload = fragment_chunk.ljust(28, b'\x00')

# Fragment-level encryption
packet_id_bytes = struct.pack('!I', packet_id)
nonce = packet_id_bytes + flags_bytes  # 8 bytes total
nonce_12 = nonce + b'\x00\x00\x00\x00'  # Pad to 12 bytes for ChaCha20
encrypted_payload = chacha20_encrypt(enc_key, nonce_12, payload)

# Compute MAC over encrypted payload
fragment_mac = poly1305(frag_key, encrypted_payload)[:4]

# Assemble wire packet
wire_packet = packet_id_bytes + flags_bytes + fragment_mac + encrypted_payload
# Total: 4 + 4 + 4 + 28 = 40 bytes
```

---

## Encoding: Base36

**Alphabet:** `0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ` (case-insensitive decode)

40 bytes → 63 characters (exact fit for single DNS label)

### Implementation by Language

**Python:**
```python
import base64
# Use custom base36 encoder (see reference implementation)
```

**Node.js:**
```javascript
// Use base-x or custom implementation
const BASE36 = '0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ';
```

**Go:**
```go
import "math/big"
// Use big.Int for base conversion
```

**Rust:**
```rust
// Use num-bigint crate
```

**C:**
```c
// Manual implementation with division/modulo
```

---

## Cryptographic Primitives

### ChaCha20 Encryption

**Nonce:** 12 bytes (8 bytes from packet_id+flags, zero-padded)
**Key:** 32 bytes (derived keys)
**Block counter:** Starts at 0

**Libraries:**
- Python: `cryptography.hazmat.primitives.ciphers`
- Node.js: `tweetnacl` (XChaCha20) or Node crypto module
- Go: `golang.org/x/crypto/chacha20`
- Rust: `chacha20` crate
- C: `libsodium` (`crypto_stream_chacha20`)

### Poly1305 MAC

**Key:** 32 bytes (one-time)
**Output:** 16 bytes (truncate to 4 or 8 bytes as needed)

**Libraries:**
- Python: Implement manually or use `cryptography`
- Node.js: `tweetnacl` (`crypto_onetimeauth`)
- Go: `golang.org/x/crypto/poly1305`
- Rust: `poly1305` crate
- C: `libsodium` (`crypto_onetimeauth_poly1305`)

---

## DNS Query Format

```
<63-character-base36-fragment>.<domain>

Example:
X3K9LABC...DEF123.asd.qwe
```

**Sending:**
- Use system DNS resolver
- Type A query (any type works, server only captures)
- No response needed (one-way covert channel)

---

## Client Interface

Every client MUST implement this interface:

### Class: `MumbojumboClient`

**Constructor:**
```
MumbojumboClient(client_key, domain, [max_packet_id=None])
```

**Methods:**
1. `send(key, value)` → Send key-value pair via DNS
2. `send_data(data)` → Send raw data with empty key
3. `upload_file(filepath, remote_path)` → Upload file with `u://` key

**Internal State:**
- `client_key` - 32-byte master key
- `enc_key, auth_key, frag_key` - Derived keys
- `domain` - DNS suffix (e.g., `.asd.qwe`)
- `packet_id_counter` - Auto-increment u32 (wraps at 2^32)

### Required Functions

Clients MUST implement these functions:

1. **Key Management:**
   - `parse_key(key_str)` - Parse `mj_cli_<hex>` → 32 bytes
   - `derive_keys(client_key)` - KDF → (enc_key, auth_key, frag_key)

2. **Message Building:**
   - `build_plaintext(key, value)` - Create key-value plaintext
   - `inner_encrypt(plaintext, enc_key, auth_key)` - Message-level encryption
   - `fragment_message(message)` - Split into 28-byte chunks

3. **Fragment Building:**
   - `build_flags(is_first, has_more, index)` - Create flags u32
   - `outer_encrypt(payload, enc_key, packet_id, flags)` - Fragment encryption
   - `compute_fragment_mac(encrypted_payload, frag_key)` - 4-byte MAC
   - `build_wire_packet(packet_id, flags, mac, encrypted_payload)` - 40 bytes

4. **Encoding & Sending:**
   - `base36_encode(data)` - 40 bytes → 63 chars
   - `send_dns_query(label, domain)` - Issue DNS query

---

## Full Send Algorithm

```python
def send(key, value, client_key, domain):
    # 1. Derive keys
    enc_key, auth_key, frag_key = derive_keys(client_key)

    # 2. Build plaintext
    plaintext = bytes([len(key)]) + key + value

    # 3. Inner encryption (message level)
    nonce_inner = os.urandom(8)
    encrypted_kv = chacha20_encrypt(enc_key, nonce_inner, plaintext)
    integrity = poly1305(auth_key, nonce_inner + encrypted_kv)[:8]
    message = nonce_inner + integrity + encrypted_kv

    # 4. Fragment into 28-byte chunks
    packet_id = random.randint(0, 0xFFFFFFFF)
    fragments = [message[i:i+28] for i in range(0, len(message), 28)]

    # 5. Build and send each fragment
    for i, chunk in enumerate(fragments):
        is_first = (i == 0)
        has_more = (i < len(fragments) - 1)

        # Build flags (UNENCRYPTED)
        flags = (is_first << 31) | (has_more << 30) | i
        flags_bytes = struct.pack('!I', flags)

        # Pad to 28 bytes
        payload = chunk.ljust(28, b'\x00')

        # Fragment encryption
        packet_id_bytes = struct.pack('!I', packet_id)
        nonce = packet_id_bytes + flags_bytes + b'\x00\x00\x00\x00'
        encrypted_payload = chacha20_encrypt(enc_key, nonce, payload)

        # MAC
        mac = poly1305(frag_key, encrypted_payload)[:4]

        # Wire packet
        wire = packet_id_bytes + flags_bytes + mac + encrypted_payload

        # Encode and send
        label = base36_encode(wire)
        send_dns_query(f"{label}{domain}")
```

---

## Testing & Validation

### Test Vectors

Implement these test cases:

1. **Single-fragment message:** `key=""`, `value=b"HI"`
2. **Multi-fragment message:** `key="test"`, `value=b"A"*100`
3. **Upload protocol:** `key="u://test.txt"`, `value=b"file contents"`
4. **Large key:** `key="x"*255`, `value=b"y"`

### Validation

Compare your client's output with Python reference:

```bash
# Generate same packet_id test
echo "test" | ./mumbojumbo-client.py -k mj_cli_... -d .test.com

# Compare Base36-encoded fragments
```

---

## Environment Variables

Support these for auto-configuration:

- `MUMBOJUMBO_CLIENT_KEY` - Master key (mj_cli_...)
- `MUMBOJUMBO_DOMAIN` - DNS suffix (.example.com)

**Priority:** CLI args > Environment > Config file

---

## Error Handling

Clients MUST handle:

1. **Invalid key format:** Reject non-hex, wrong length, wrong prefix
2. **DNS failures:** Retry or report (don't crash)
3. **Empty data:** Reject or send minimum 1-byte value
4. **Large data:** Warn if >30GB (protocol maximum)

---

## Security Notes

- **Keep keys secret:** Master key is symmetric (shared by all)
- **No authentication:** Anyone with key can send
- **No confidentiality of metadata:** Flags are unencrypted
- **Replay attacks:** No timestamp protection
- **Use for authorized testing only**

---

## Implementation Checklist

- [ ] Parse `mj_cli_` key format
- [ ] Implement Poly1305-based KDF
- [ ] Implement ChaCha20 encryption
- [ ] Implement Poly1305 MAC
- [ ] Build key-value plaintext
- [ ] Inner encryption with nonce + integrity
- [ ] Fragment into 28-byte chunks
- [ ] Build fragment flags correctly
- [ ] Outer encryption with packet_id + flags nonce
- [ ] Compute 4-byte fragment MAC
- [ ] Assemble 40-byte wire packets
- [ ] Base36 encode to 63 characters
- [ ] Send DNS queries
- [ ] Support environment variables
- [ ] Handle upload protocol (`u://` keys)
- [ ] Test against Python reference

---

## Additional Resources

- [PROTOCOL.md](../PROTOCOL.md) - Complete protocol specification
- [clients/python/mumbojumbo-client.py](python/mumbojumbo-client.py) - Reference implementation
- [clients/python/API.md](python/API.md) - Python API documentation
- [RFC 7539](https://tools.ietf.org/html/rfc7539) - ChaCha20 and Poly1305

---

**NOTE:** The Python client is the authoritative implementation. When in doubt, match Python's behavior exactly.
