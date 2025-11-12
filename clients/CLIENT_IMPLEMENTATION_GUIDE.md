# Multi-Language Client Implementation Guide

This guide provides the exact specifications for implementing mumbojumbo clients in Node.js, Go, Rust, and C.

## Reference Implementation: Python ✅

The Python client ([clients/python/mumbojumbo-client.py](python/mumbojumbo-client.py)) is the reference implementation. All other clients MUST follow the same pattern and protocol.

---

## Protocol Specification

### Fragment Header Format (12 bytes)

All fields in **big-endian** (network byte order):

```
Bytes  0-1:  packet_id      (u16) - Packet identifier (0-65535)
Bytes  2-5:  frag_index     (u32) - Fragment index (0 to count-1)
Bytes  6-9:  frag_count     (u32) - Total fragments (up to 4.3 billion)
Bytes 10-11: frag_data_len  (u16) - Fragment data length (0-80 bytes)
Bytes 12+:   frag_data      (var) - Actual data (max 80 bytes)
```

### Struct Definitions by Language

**Python:**
```python
struct.pack('!HIIH', packet_id, frag_index, frag_count, data_len)
# ! = big-endian, H = u16, I = u32
```

**Node.js / JavaScript:**
```javascript
const buffer = Buffer.allocUnsafe(12);
buffer.writeUInt16BE(packet_id, 0);
buffer.writeUInt32BE(frag_index, 2);
buffer.writeUInt32BE(frag_count, 6);
buffer.writeUInt16BE(data_len, 10);
```

**Go:**
```go
binary.BigEndian.PutUint16(header[0:2], packet_id)
binary.BigEndian.PutUint32(header[2:6], frag_index)
binary.BigEndian.PutUint32(header[6:10], frag_count)
binary.BigEndian.PutUint16(header[10:12], data_len)
```

**Rust:**
```rust
header[0..2].copy_from_slice(&packet_id.to_be_bytes());
header[2..6].copy_from_slice(&frag_index.to_be_bytes());
header[6..10].copy_from_slice(&frag_count.to_be_bytes());
header[10..12].copy_from_slice(&data_len.to_be_bytes());
```

**C:**
```c
uint16_t packet_id_be = htons(packet_id);
uint32_t frag_index_be = htonl(frag_index);
uint32_t frag_count_be = htonl(frag_count);
uint16_t data_len_be = htons(data_len);

memcpy(header + 0, &packet_id_be, 2);
memcpy(header + 2, &frag_index_be, 4);
memcpy(header + 6, &frag_count_be, 4);
memcpy(header + 10, &data_len_be, 2);
```

---

## Client Class/Module Design

Every client MUST implement this exact interface:

### Class: `MumbojumboClient`

**Constructor:**
```
MumbojumboClient(server_public_key, domain, [max_fragment_size=80])
```

**Methods:**
1. `send_data(data, [send_queries=true])` → `[(query, success), ...]`
2. `generate_queries(data)` → `[query1, query2, ...]`

**Internal State:**
- `_next_packet_id` - Auto-incrementing u16 counter (wraps at 0xFFFF)
- `server_client_key` - Server's public key (32 bytes)
- `domain` - DNS domain suffix (e.g., `.asd.qwe`)
- `max_fragment_size` - Max bytes per fragment (default: 80)

### Helper Functions

All clients MUST provide these helpers (can be private):

1. **`parse_key_hex(key_str)`** - Parse `mj_cli_<hex>` format
2. **`create_fragment(packet_id, frag_index, frag_count, frag_data)`** - Build 12-byte header + data
3. **`encrypt_fragment(plaintext, server_client_key)`** - NaCl SealedBox encryption
4. **`base32_encode(data)`** - Lowercase, no padding
5. **`split_to_labels(data, max_len=63)`** - Split into DNS labels
6. **`create_dns_query(encrypted, domain)`** - Full DNS name
7. **`send_dns_query(dns_name)`** - Send via system DNS resolver
8. **`fragment_data(data, max_size=80)`** - Split data into chunks

---

## Encryption: NaCl SealedBox

All clients use **NaCl SealedBox** for anonymous public-key encryption.

### Libraries by Language

| Language | Library | Package |
|----------|---------|---------|
| Python | `pynacl` | `nacl.public.SealedBox` |
| Node.js | `tweetnacl` + `tweetnacl-sealedbox-js` | `sealedbox.seal()` |
| Go | `golang.org/x/crypto/nacl/box` | Custom SealedBox wrapper |
| Rust | `sodiumoxide` | `sealedbox::seal()` |
| C | `libsodium` | `crypto_box_seal()` |

### Encryption Details

- **Algorithm:** X25519 (key exchange) + XSalsa20-Poly1305 (encryption)
- **Overhead:** 48 bytes (32-byte ephemeral public key + 16-byte auth tag)
- **Client needs:** Only server's public key (32 bytes)
- **Server needs:** Its private key (32 bytes) for decryption
- **Nonce:** Handled automatically by SealedBox

---

## Base32 Encoding

- **Alphabet:** `ABCDEFGHIJKLMNOPQRSTUVWXYZ234567`
- **Output:** Lowercase (`abcdefghijklmnopqrstuvwxyz234567`)
- **Padding:** NONE - remove all `=` characters
- **Standard:** RFC 4648

### Implementation by Language

**Python:**
```python
base64.b32encode(data).replace(b'=', b'').lower().decode('ascii')
```

**Node.js:**
```javascript
const base32 = require('base32');
base32.encode(data).replace(/=/g, '').toLowerCase();
```

**Go:**
```go
base32.StdEncoding.EncodeToString(data)
// Convert to lowercase, remove padding
```

**Rust:**
```rust
use base32;
base32::encode(base32::Alphabet::RFC4648 { padding: false }, data).to_lowercase()
```

**C:**
```c
// Manual implementation or use base32.c library
```

---

## DNS Query Encoding

After base32 encoding:

1. **Split into 63-character labels**
   - DNS label max length: 63 characters
   - Split string every 63 chars

2. **Join with dots**
   - `label1.label2.label3`

3. **Append domain suffix**
   - Final: `label1.label2.label3.asd.qwe`

### Example

```
Encrypted: [71 bytes]
Base32: "jjvruxg4bfjrq2lbmfxgs43pn5tuk6bqmfzwk5dzn7ytgu3fmeza"
Labels: ["jjvruxg4bfjrq2lbmfxgs43pn5tuk6bqmfzwk5dzn7ytgu3fmeza"]
DNS: "jjvruxg4bfjrq2lbmfxgs43pn5tuk6bqmfzwk5dzn7ytgu3fmeza.asd.qwe"
```

---

## CLI Interface

All clients MUST support the same command-line interface:

### Arguments

- `-k, --key <public_key>` - Server public key (mj_cli_... format) **REQUIRED**
- `-d, --domain <domain>` - DNS domain suffix (e.g., `.asd.qwe`) **REQUIRED**
- `-f, --file <path>` - Input file path, use `-` for stdin (default: stdin)
- `-v, --verbose` - Enable verbose output to stderr

### Examples

```bash
# Send from stdin
echo "Hello" | ./mumbojumbo-client -k mj_cli_... -d .asd.qwe

# Send from file
./mumbojumbo-client -k mj_cli_... -d .asd.qwe -f message.txt

# Verbose mode
./mumbojumbo-client -k mj_cli_... -d .asd.qwe -v
```

### Output

**stdout:** DNS query names (one per line)
**stderr:** Verbose info (only if `-v` flag)

---

## Complete Data Flow

```
1. Read input (file or stdin)
2. Initialize client with server public key and domain
3. Split data into 80-byte chunks (fragments)
4. For each fragment:
   a. Build 12-byte header (packet_id, frag_index, frag_count, data_len)
   b. Append fragment data
   c. Encrypt with NaCl SealedBox
   d. Base32 encode (lowercase, no padding)
   e. Split into 63-char labels
   f. Join labels with dots
   g. Append domain
   h. Send DNS query (or just generate if dry-run)
5. Return results
```

---

## Testing Requirements

Each client MUST have comprehensive tests covering:

### Unit Tests
- Key parsing (valid, invalid, wrong format)
- Fragment header creation (basic, multi-fragment, empty, oversized)
- Encryption/decryption round-trips
- Base32 encoding (basic, no padding, lowercase)
- DNS label splitting (short, long, exactly 63 chars, empty)
- Data fragmentation (small, exact size, overflow)

### Integration Tests
- Client initialization
- Query generation without sending
- Multi-fragment messages
- Internal packet ID management (not exposed to users)

### End-to-End Tests
- Full encrypt → encode → decode → decrypt flow
- Single-fragment messages
- Multi-fragment messages
- CLI interface (help, missing args, stdin, file input)

### Cross-Compatibility Tests
- All clients MUST generate identical DNS queries for same input
- All clients MUST work with Python server (mumbojumbo.py)

---

## Implementation Checklist

For each language:

- [ ] Create client directory structure
- [ ] Implement `MumbojumboClient` class/module
  - [ ] Constructor with key, domain, max_fragment_size
  - [ ] `send_data()` method
  - [ ] `generate_queries()` method
  - [ ] Internal packet ID management
- [ ] Implement helper functions
  - [ ] `parse_key_hex()`
  - [ ] `create_fragment()` with 12-byte header
  - [ ] `encrypt_fragment()` with NaCl SealedBox
  - [ ] `base32_encode()`
  - [ ] `split_to_labels()`
  - [ ] `create_dns_query()`
  - [ ] `send_dns_query()`
  - [ ] `fragment_data()`
- [ ] Implement CLI wrapper
  - [ ] Argument parsing (-k, -d, -f, -v)
  - [ ] File/stdin input
  - [ ] Verbose output
- [ ] Write comprehensive tests
  - [ ] Unit tests (all helpers)
  - [ ] Integration tests (client class)
  - [ ] E2E tests (full flow)
  - [ ] CLI tests
- [ ] Cross-compatibility testing
  - [ ] Generate same queries as Python client
  - [ ] Test against Python server
- [ ] Documentation
  - [ ] README.md
  - [ ] API.md
  - [ ] Usage examples

---

## Language-Specific Notes

### Node.js
- Use ES6 modules or CommonJS
- Single file or minimal package
- Dependencies: `tweetnacl`, `tweetnacl-sealedbox-js`
- Test framework: Jest or Node test runner

### Go
- Use standard library where possible
- Single package or minimal module
- Dependencies: `golang.org/x/crypto/nacl/box`
- Implement custom SealedBox wrapper
- Test framework: `go test`

### Rust
- Use Cargo project
- Dependencies: `sodiumoxide` or `crypto_box`
- Minimize external crates
- Test framework: Built-in `cargo test`

### C
- Single .c file or minimal project
- Dependencies: `libsodium` only
- Manual base32 implementation or minimal library
- Test framework: Check or minimal custom harness

---

## Key Design Principles

1. **Simplicity** - Single file or minimal dependencies
2. **Consistency** - All clients follow exact same pattern
3. **Modularity** - Clean class/module interface
4. **Testability** - Comprehensive test coverage
5. **Compatibility** - Work with Python server
6. **No backwards compatibility** - Always use latest/greatest
7. **Clean API** - Packet ID is internal, not exposed

---

## Reference: Python Client API

```python
from mumbojumbo_client import MumbojumboClient, parse_key_hex

# Initialize
key = parse_key_hex('mj_cli_abc123...')
client = MumbojumboClient(key, '.asd.qwe')

# Send data
results = client.send_data(b"Hello World")
for dns_query, success in results:
    print(f"{dns_query}: {'✓' if success else '✗'}")

# Or just generate queries
queries = client.generate_queries(b"Test")
for query in queries:
    print(query)
```

This is the pattern ALL clients must follow!
