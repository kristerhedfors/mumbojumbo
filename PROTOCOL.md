# Mumbojumbo Protocol Specification

## Overview

Mumbojumbo is a DNS tunneling protocol that provides covert, encrypted communication over DNS queries. It uses NaCl (libsodium) public key cryptography via SealedBox for anonymous one-way encryption. Messages are fragmented into manageable chunks, encoded as base32, and transmitted as DNS subdomain queries.

**Use Cases:** Educational purposes, authorized security testing, CTF challenges, network research.

**Security Warning:** This is a demonstration implementation. It lacks timestamp protection, perfect forward secrecy, and rate limiting. Do not use for production or sensitive data.

---

## Protocol Architecture

```
┌─────────────────────────────────────────────────────────────────────┐
│                         CLIENT SIDE                                  │
├─────────────────────────────────────────────────────────────────────┤
│                                                                       │
│  Plaintext Message: "Hello World!"                                   │
│           │                                                           │
│           ▼                                                           │
│  ┌─────────────────────────────────────────────────────────────┐   │
│  │  Step 1: Fragment Message (auto-sized based on domain)      │   │
│  │                                                               │   │
│  │  Fragment 0: packet_id=0xABCD1234, index=0, count=3         │   │
│  │  Fragment 1: packet_id=0xABCD1234, index=1, count=3         │   │
│  │  Fragment 2: packet_id=0xABCD1234, index=2, count=3         │   │
│  └─────────────────────────────────────────────────────────────┘   │
│           │                                                           │
│           ▼                                                           │
│  ┌─────────────────────────────────────────────────────────────┐   │
│  │  Step 2: Encrypt each fragment with NaCl SealedBox         │   │
│  │  (Mumbojumbo Public Key - anonymous one-way encryption)     │   │
│  │                                                               │   │
│  │  Encrypted Payload (SealedBox handles nonce internally)     │   │
│  └─────────────────────────────────────────────────────────────┘   │
│           │                                                           │
│           ▼                                                           │
│  ┌─────────────────────────────────────────────────────────────┐   │
│  │  Step 3: Base32 Encode (DNS-safe)                           │   │
│  │                                                               │   │
│  │  4qd7...xyl5 (lowercase, no padding)                         │   │
│  └─────────────────────────────────────────────────────────────┘   │
│           │                                                           │
│           ▼                                                           │
│  ┌─────────────────────────────────────────────────────────────┐   │
│  │  Step 4: Split into 63-char DNS labels                      │   │
│  │                                                               │   │
│  │  4qd7...xyz.abc1...def2.gh34...jkl5.asd.qwe                │   │
│  └─────────────────────────────────────────────────────────────┘   │
│           │                                                           │
│           ▼                                                           │
│  DNS Query: 4qd7...xyz.abc1...def2.gh34...jkl5.asd.qwe            │
│                                                                       │
└───────────────────────────────┬───────────────────────────────────────┘
                                │
                    ┌───────────▼───────────┐
                    │   DNS Infrastructure   │
                    │                        │
                    │  Query propagates      │
                    │  through DNS system    │
                    └───────────┬───────────┘
                                │
┌───────────────────────────────▼───────────────────────────────────────┐
│                         SERVER SIDE                                    │
├─────────────────────────────────────────────────────────────────────┤
│                                                                       │
│  ┌─────────────────────────────────────────────────────────────┐   │
│  │  Step 1: Capture DNS Queries (tshark)                       │   │
│  │                                                               │   │
│  │  tshark -li en0 -T fields -e dns.qry.name -- udp port 53    │   │
│  └─────────────────────────────────────────────────────────────┘   │
│           │                                                           │
│           ▼                                                           │
│  ┌─────────────────────────────────────────────────────────────┐   │
│  │  Step 2: Filter by Domain (.asd.qwe)                       │   │
│  └─────────────────────────────────────────────────────────────┘   │
│           │                                                           │
│           ▼                                                           │
│  ┌─────────────────────────────────────────────────────────────┐   │
│  │  Step 3: Base32 Decode (remove labels, add padding)         │   │
│  └─────────────────────────────────────────────────────────────┘   │
│           │                                                           │
│           ▼                                                           │
│  ┌─────────────────────────────────────────────────────────────┐   │
│  │  Step 4: Decrypt with NaCl SealedBox                        │   │
│  │  (Mumbojumbo Private Key - server decrypts anonymously)    │   │
│  └─────────────────────────────────────────────────────────────┘   │
│           │                                                           │
│           ▼                                                           │
│  ┌─────────────────────────────────────────────────────────────┐   │
│  │  Step 5: Parse Fragment Header                              │   │
│  │                                                               │   │
│  │  Packet ID, Fragment Index, Fragment Count, Data Length     │   │
│  └─────────────────────────────────────────────────────────────┘   │
│           │                                                           │
│           ▼                                                           │
│  ┌─────────────────────────────────────────────────────────────┐   │
│  │  Step 6: Reassemble Fragments                               │   │
│  │                                                               │   │
│  │  Wait for all fragments (count=3) matching packet_id        │   │
│  │  Sort by fragment index, concatenate data                    │   │
│  └─────────────────────────────────────────────────────────────┘   │
│           │                                                           │
│           ▼                                                           │
│  Complete Message: "Hello World!"                                    │
│           │                                                           │
│           ▼                                                           │
│  ┌─────────────────────────────────────────────────────────────┐   │
│  │  Step 7: Forward (Optional)                                 │   │
│  │                                                               │   │
│  │  • Print to stdout                                           │   │
│  │  • Email via SMTP                                            │   │
│  │  • Custom forwarder                                          │   │
│  └─────────────────────────────────────────────────────────────┘   │
│                                                                       │
└─────────────────────────────────────────────────────────────────────┘
```

---

## DNS Fragment Sizing

### Automatic Fragment Size Calculation

Mumbojumbo automatically calculates the maximum safe fragment data size based on the domain name length. This ensures DNS name constraints are never violated while maximizing throughput.

**Formula:** `83 - len(domain) / 3`

**Why this formula?**

To fit data within DNS constraints, we need to account for:
- **Fragment header:** 18 bytes (packet_id + index + count + data_len + key_len)
- **Encryption overhead:** 48 bytes (NaCl SealedBox: 32-byte ephemeral key + 16-byte auth tag)
- **Base32 encoding:** 1.6× expansion (5 bits per character)
- **DNS label limits:** Maximum 63 characters per label, 253 total name length
- **Domain suffix:** Variable length (e.g., `.asd.qwe` = 8 bytes)

The formula `83 - len(domain) / 3` provides a simple linear approximation that:
- **Stays well within DNS limits** for all reasonable domain lengths
- **Is within 2 bytes of optimal** for typical domains (3-12 characters)
- **Requires only one arithmetic operation** instead of complex calculations
- **Trades ~5% efficiency for extreme simplicity and safety**

### DNS Constraints

```
RFC 1035 DNS Limits:
• Maximum DNS name length: 253 bytes
• Maximum DNS label length: 63 bytes
• Domain suffix: variable (e.g., ".asd.qwe" = 8 bytes)
```

### Domain Length Examples

| Domain | Length | Fragment Size |
|--------|--------|---------------|
| `.xy` | 3 bytes | 82 bytes |
| `.asd.qwe` | 8 bytes | 81 bytes |
| `.example.com` | 12 bytes | 79 bytes |
| `.subdomain.example.com` | 22 bytes | 76 bytes |

### Maximum Domain Length

For communication to work, domains cannot exceed **~143 characters** (which would leave room for only 1 byte of fragment data).

---

## Binary Packet Format

### Fragment Structure

Each fragment consists of a header followed by payload data:

```
 0                   1                   2                   3
 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
┌───────────────────────────────────────────────────────────────┐
│                                                               │
│                     Packet ID (u64)                           │
│                   (Network Byte Order)                        │
│                                                               │
├───────────────────────────────────────────────────────────────┤
│                                                               │
│                   Fragment Index (u32)                        │
│                   (Network Byte Order)                        │
│                                                               │
├───────────────────────────────────────────────────────────────┤
│                                                               │
│                   Fragment Count (u32)                        │
│                   (Network Byte Order)                        │
│                                                               │
├───────────────────────────────┬───────────────────────────────┤
│  Data Length (u8) │ Key Len   │                               │
│                   │   (u8)    │                               │
├───────────────────────────────┤    Fragment Data (variable)   │
│                               │                               │
│                               │         (0-83 bytes)          │
│                               │                               │
└───────────────────────────────┴───────────────────────────────┘

Total Header Size: 18 bytes (u64 + u32 + u32 + u8 + u8)
Max Fragment Data: Auto-calculated from domain length (typically 71-82 bytes)
Max Fragment Size: ~89-100 bytes (depending on domain)
```

### Field Descriptions

| Field | Size | Type | Description |
|-------|------|------|-------------|
| **Packet ID** | 8 bytes | u64 (big-endian) | Sequential identifier for the complete message (0 to 2^64-1, wraps around). All fragments of the same message share this ID. Generated by incrementing counter. |
| **Fragment Index** | 4 bytes | u32 (big-endian) | Zero-based index of this fragment (0 to count-1). Supports up to 4.3 billion fragments. Used for ordering during reassembly. |
| **Fragment Count** | 4 bytes | u32 (big-endian) | Total number of fragments in this message. Supports up to 4.3 billion fragments. Same for all fragments with matching Packet ID. |
| **Data Length** | 1 byte | u8 | Length of the fragment data field (0-255 bytes). Must match actual data length. Never exceeds 83 bytes in practice due to DNS constraints. |
| **Key Length** | 1 byte | u8 | Length of the key in the reassembled packet (0-255 bytes). If non-zero, the first `key_len` bytes of the reassembled packet are the key, the rest is the value. Used for key-value transmissions (e.g., filename + file content). |
| **Fragment Data** | variable | bytes | Raw message payload for this fragment. Maximum calculated from domain (see DNS Fragment Sizing section). |

### Protocol Capacity

With the current limits:
- **Maximum fragments per packet:** 4,294,967,295 (2³² - 1)
- **Fragment data size:** Auto-calculated (typically 71-82 bytes based on domain)
- **Maximum packet size:** ~300 GB+ (varies with domain length)
- **Practical use:** Easily supports multi-GB file transfers

### Key-Value Transmission

Mumbojumbo supports optional key-value transmission mode, useful for file transfers where the key is naturally the filename:

**How it works:**

1. **Client prepares data:** `key + value` (e.g., `b"document.pdf" + file_contents`)
2. **Client sets key_len:** All fragments carry `key_len` in header (e.g., 12 for "document.pdf")
3. **Server reassembles:** Fragments are reassembled normally into complete data block
4. **Server splits data:** First `key_len` bytes become the key, remaining bytes become the value

**Example:**

```python
# Client sends file
client.send_kv(b"report.pdf", pdf_contents)

# Server receives as key-value pair
# Output JSON:
{
  "event": "packet_reassembled",
  "key_length": 10,
  "value_length": 52481,
  "key_preview": "report.pdf",
  "value_preview": "%PDF-1.4..."
}
```

**Use Cases:**
- File transfers with filename metadata
- Key-value storage operations
- Label + data transmissions
- Any application requiring binary key-value pairs

**Validation Rules:**
- **Key**: May be zero-length (`key_len=0`) or up to 255 bytes
  - In client APIs: `key=None` converts to zero-length key (`b''`)
  - Zero-length key = "null key" or "data-only mode"
- **Value**: MUST be at least 1 byte (non-empty)
  - In client APIs: `value=None` or `value=b''` raises `ValueError`
  - Empty values are not permitted in key-value mode
- Key + value combined size subject to normal fragmentation limits
- Key length is the same across all fragments of a packet

**Limitations:**
- Key length cannot exceed 255 bytes (u8 constraint)
- Value cannot be empty (minimum 1 byte required)

---

## Encryption Layer

Mumbojumbo uses NaCl (libsodium) public-key anonymous encryption via `nacl.public.SealedBox`. This provides one-way encryption where clients only need the server's public key.

### Key Exchange

```
┌──────────────────────────────────────────────────────────────┐
│                  Key Generation & Exchange                    │
├──────────────────────────────────────────────────────────────┤
│                                                               │
│  Server Side:                                                 │
│  ┌────────────────────────────────────────────────────────┐ │
│  │ $ ./mumbojumbo.py --gen-keys                            │ │
│  │                                                          │ │
│  │ Generates (hex format with prefixes):                   │ │
│  │   • Server Private Key: mj_srv_<64_hex_chars>           │ │
│  │   • Client Public Key: mj_cli_<64_hex_chars>            │ │
│  │   • Random Domain: .xxxx.yyyy                           │ │
│  │                                                          │ │
│  │ Output: Environment variable declarations               │ │
│  │ export MUMBOJUMBO_SERVER_KEY=mj_srv_...                │ │
│  │ export MUMBOJUMBO_CLIENT_KEY=mj_cli_...                │ │
│  │ export MUMBOJUMBO_DOMAIN=.asd.qwe                      │ │
│  └────────────────────────────────────────────────────────┘ │
│                                                               │
│  Configuration File (mumbojumbo.conf):                        │
│  ┌────────────────────────────────────────────────────────┐ │
│  │ [main]                                                   │ │
│  │ domain = .asd.qwe                                       │ │
│  │ network-interface = en0                                  │ │
│  │ handlers = stdout                                        │ │
│  │ mumbojumbo-server-key = mj_srv_3f55...cb72 (hex)       │ │
│  │ mumbojumbo-client-key = mj_cli_0630...b679 (hex)       │ │
│  └────────────────────────────────────────────────────────┘ │
│                                                               │
│  Out-of-Band Transfer:                                        │
│  ┌────────────────────────────────────────────────────────┐ │
│  │ Client receives via secure channel:                     │ │
│  │   • mumbojumbo_client_key = mj_cli_<64_hex>            │ │
│  │   • domain = .asd.qwe                                   │ │
│  └────────────────────────────────────────────────────────┘ │
│                                                               │
└──────────────────────────────────────────────────────────────┘
```

### Encryption Process

Each fragment undergoes the following encryption using SealedBox:

```python
# Client Side (Transmission)
plaintext = serialize_fragment(packet_id, frag_index, frag_count, data)
sealedbox = nacl.public.SealedBox(mumbojumbo_public_key)
ciphertext = sealedbox.encrypt(plaintext)
# SealedBox handles nonce internally - no manual nonce management needed
# Overhead: 48 bytes (32-byte ephemeral public key + 16-byte auth tag)

# Server Side (Reception)
sealedbox = nacl.public.SealedBox(mumbojumbo_private_key)
plaintext = sealedbox.decrypt(ciphertext)
fragment = parse_fragment(plaintext)
```

**Security Properties:**
- **Anonymous:** Server cannot identify the sender by cryptographic means
- **Confidentiality:** Only the server with the private key can decrypt messages
- **Integrity:** Any tampering is detected during decryption
- **Simplicity:** Client only needs the public key (no client keypair required)

**Limitations:**
- ⚠️ **No authentication:** Server cannot verify sender identity
- ⚠️ **No replay protection:** Old messages can be replayed
- ⚠️ **No forward secrecy:** Compromised keys expose all past messages
- ⚠️ **No timestamp validation:** Messages can be delayed or reordered
- ⚠️ **Higher overhead:** 48 bytes vs 20 bytes (Box with 4-byte nonce)

---

## DNS Encoding

### Base32 Encoding

Mumbojumbo uses RFC 4648 Base32 encoding with modifications for DNS compatibility:

```
Standard Base32 Alphabet: ABCDEFGHIJKLMNOPQRSTUVWXYZ234567
Mumbojumbo Modifications:
  • Convert to lowercase: abcdefghijklmnopqrstuvwxyz234567
  • Remove padding '=' characters
  • Reason: DNS labels are case-insensitive and padding is unnecessary
```

### DNS Label Construction

DNS has strict limitations on label length and format:

```
┌──────────────────────────────────────────────────────────────┐
│                  DNS Label Constraints                        │
├──────────────────────────────────────────────────────────────┤
│                                                               │
│  • Maximum label length: 63 characters                        │
│  • Maximum total name length: 253 characters                  │
│  • Valid characters: [a-z0-9-] (case-insensitive)            │
│  • Labels separated by dots (.)                               │
│                                                               │
│  Example Encoded Fragment:                                    │
│  ┌────────────────────────────────────────────────────────┐ │
│  │                                                          │ │
│  │  Encrypted bytes: [0x4A, 0x7B, 0x2C, 0xDE, ...]        │ │
│  │         │                                                │ │
│  │         ▼                                                │ │
│  │  Base32: jjvruxg4bfjrq2lbmfxgs43pn5tuk6bqmfzwk          │ │
│  │         │                                                │ │
│  │         ▼ (split every 63 chars)                        │ │
│  │  Label 1: jjvruxg4bfjrq2lbmfxgs43pn5tuk6bqmfzwk        │ │
│  │         │ (59 chars, fits in one label)                 │ │
│  │         ▼                                                │ │
│  │  DNS Name:                                               │ │
│  │    jjvruxg4bfjrq2lbmfxgs43pn5tuk6bqmfzwk.asd.qwe       │ │
│  │                                                          │ │
│  │  Longer Fragment:                                        │ │
│  │  Base32 (150 chars):                                     │ │
│  │    abcdefgh...xyz (imagine this is 150 chars)           │ │
│  │         │                                                │ │
│  │         ▼ (split at 63-char boundaries)                 │ │
│  │  Label 1: abcdefgh...xyz (63 chars)                     │ │
│  │  Label 2: mnopqrst...uvw (63 chars)                     │ │
│  │  Label 3: defghijk...mno (24 chars)                     │ │
│  │         │                                                │ │
│  │         ▼                                                │ │
│  │  DNS Name:                                               │ │
│  │    <label1>.<label2>.<label3>.asd.qwe                  │ │
│  │                                                          │ │
│  └────────────────────────────────────────────────────────┘ │
│                                                               │
└──────────────────────────────────────────────────────────────┘
```

### Example: Complete Encoding

```python
# Input: Encrypted fragment (binary)
encrypted = b'\x4a\x7b\x2c\xde\xf1\x23\x45\x67\x89\xab\xcd\xef'

# Step 1: Base32 encode
base32 = base32_encode(encrypted)  # "jjvruxg4bfjrq2lbmfxgs43pn5tuk6bq"

# Step 2: Split into 63-character chunks
labels = split_every_63_chars(base32)  # ["jjvruxg4bfjrq2lbmfxgs43pn5tuk6bq"]

# Step 3: Join with dots and add domain
dns_name = ".".join(labels) + ".asd.qwe"
# Result: "jjvruxg4bfjrq2lbmfxgs43pn5tuk6bq.asd.qwe"

# This DNS name is now queried by the client
# The query propagates through DNS infrastructure
# The server captures it using tshark
```

---

## Fragment Reassembly

The server maintains state for incomplete messages:

```
┌──────────────────────────────────────────────────────────────┐
│              Fragment Reassembly State Machine                │
├──────────────────────────────────────────────────────────────┤
│                                                               │
│  Data Structures:                                             │
│  ┌────────────────────────────────────────────────────────┐ │
│  │ packet_assembly = {                                     │ │
│  │   packet_id_1: [frag_0_data, None, frag_2_data, ...],  │ │
│  │   packet_id_2: [None, frag_1_data, None, ...],         │ │
│  │   ...                                                    │ │
│  │ }                                                        │ │
│  │                                                          │ │
│  │ packet_assembly_counter = {                             │ │
│  │   packet_id_1: 2,  # 2 fragments remaining             │ │
│  │   packet_id_2: 5,  # 5 fragments remaining             │ │
│  │   ...                                                    │ │
│  │ }                                                        │ │
│  └────────────────────────────────────────────────────────┘ │
│                                                               │
│  Reassembly Algorithm:                                        │
│  ┌────────────────────────────────────────────────────────┐ │
│  │                                                          │ │
│  │  1. Receive fragment F with:                            │ │
│  │     - packet_id = P                                      │ │
│  │     - frag_index = I                                     │ │
│  │     - frag_count = C                                     │ │
│  │     - frag_data = D                                      │ │
│  │                                                          │ │
│  │  2. Check if packet_id P exists in packet_assembly:    │ │
│  │     NO  → Create array of C None values                 │ │
│  │           Set counter[P] = C                            │ │
│  │     YES → Verify frag_count matches existing            │ │
│  │                                                          │ │
│  │  3. Check if position I is empty (None):                │ │
│  │     NO  → Ignore (duplicate fragment)                   │ │
│  │     YES → Continue to step 4                            │ │
│  │                                                          │ │
│  │  4. Insert fragment:                                     │ │
│  │     packet_assembly[P][I] = D                           │ │
│  │     counter[P] -= 1                                     │ │
│  │                                                          │ │
│  │  5. Check counter[P]:                                   │ │
│  │     > 0 → Wait for more fragments                       │ │
│  │     = 0 → All fragments received!                       │ │
│  │           Concatenate all data                          │ │
│  │           Put complete message to output queue          │ │
│  │           Clean up packet_assembly[P]                   │ │
│  │           Clean up counter[P]                           │ │
│  │                                                          │ │
│  └────────────────────────────────────────────────────────┘ │
│                                                               │
└──────────────────────────────────────────────────────────────┘
```

### Reassembly Example

```
Message: "HELLO WORLD FROM MUMBOJUMBO!" (28 bytes)
Fragment Size: 10 bytes
Result: 3 fragments

Timeline:

T=0  Fragment 2 arrives (last fragment)
     packet_assembly[0xABCD] = [None, None, "OJUMBO!"]
     counter[0xABCD] = 2 (waiting for 2 more)

T=1  Fragment 0 arrives (first fragment)
     packet_assembly[0xABCD] = ["HELLO WORL", None, "OJUMBO!"]
     counter[0xABCD] = 1 (waiting for 1 more)

T=2  Fragment 1 arrives (middle fragment)
     packet_assembly[0xABCD] = ["HELLO WORL", "D FROM MUM", "OJUMBO!"]
     counter[0xABCD] = 0 → COMPLETE!

     Reassemble: "HELLO WORL" + "D FROM MUM" + "OJUMBO!"
     Result: "HELLO WORLD FROM MUMBOJUMBO!"

     Clean up state
     Forward to output queue
```

**Important Properties:**
- **Out-of-order tolerance:** Fragments can arrive in any order
- **Duplicate detection:** Fragments received twice are ignored
- **Validation:** Fragment count must match across all fragments
- **Memory efficiency:** State is cleaned up after message completion

---

## Complete Protocol Example

### Example 1: Simple Single-Fragment Message

```
Message: "HI"
────────────────────────────────────────────────────────────────

CLIENT SIDE:
───────────
1. Input: "HI" (2 bytes)

2. Fragment:
   Packet ID: 0x1234
   Fragment 0/1 (only one fragment needed)
   ┌──────────────────┬──────────────┬──────────────┬──────────┬──────┐
   │   0x00001234     │  0x00000000  │  0x00000001  │  0x0002  │  HI  │
   │    (pkt_id)      │    (index)   │   (count)    │  (len)   │(data)│
   │      u64         │      u32     │      u32     │   u16    │ var  │
   └──────────────────┴──────────────┴──────────────┴──────────┴──────┘
   18 bytes header + 2 bytes data = 20 bytes plaintext

3. Encrypt with NaCl SealedBox:
   Plaintext: 20 bytes
   Ciphertext: 20 + 48 = 68 bytes (encrypted + 32-byte ephemeral pubkey + 16-byte auth tag)

4. Base32 Encode:
   68 bytes → 109 characters (base32)
   Result: "eizuwyzblbqwy3dfon2gs3thebswy3lpnyqhmzlsoqydamb3he2dkmztge3dsmrsmfzwizlsfyabcdefghijklmnopqrstuv"

5. Create DNS query:
   (109 chars, needs 2 labels: 63 + 46)
   DNS: eizuwyzblbqwy3dfon2gs3thebswy3lpnyqhmzlsoqydamb3he2dkmztge3dsmr.smfzwizlsfyabcdefghijklmnopqrstuv.asd.qwe

6. Send DNS query to resolver


DNS INFRASTRUCTURE:
──────────────────
Query propagates through DNS system
Recursive resolvers attempt to resolve .asd.qwe domain
Eventually reaches authoritative servers (or fails)
Server captures query via packet sniffing (tshark)


SERVER SIDE:
───────────
1. tshark captures:
   "eizuwyzblbqwy3dfon2gs3thebswy3lpnyqhmzlsoqydamb3he2dkmztge3dsmrsmfzwizlsfy.asd.qwe"

2. Filter: ends with ".asd.qwe" ✓

3. Base32 Decode:
   Remove domain and join labels: "eizuwyzblbqwy3dfon2gs3thebswy3lpnyqhmzlsoqydamb3he2dkmztge3dsmrsmfzwizlsfyabcdefghijklmnopqrstuv"
   Decode: 109 chars → 68 bytes

4. Decrypt with NaCl SealedBox:
   Ciphertext: 68 bytes
   Decrypted plaintext: 20 bytes

5. Parse Fragment (18-byte header):
   packet_id: 0x00001234 (u64)
   frag_index: 0 (u32)
   frag_count: 1 (u32)
   frag_data_len: 2 (u16)
   frag_data: "HI"

6. Reassemble:
   Only 1 fragment → immediately complete
   counter[0x00001234] = 1 - 1 = 0 ✓

7. Output:
   Message received: "HI"
   → Print to stdout or forward via SMTP
```

### Example 2: Multi-Fragment Message

```
Message: "The quick brown fox jumps over the lazy dog" (44 bytes)
Fragment Size: 15 bytes
Result: 3 fragments
────────────────────────────────────────────────────────────────

CLIENT SIDE FRAGMENTATION:
─────────────────────────
Packet ID: 0x00DEADBEEF (randomly generated u64)

Fragment 0:
  ┌──────────────────┬──────────────┬──────────────┬──────────┬────────────────────┐
  │  0x00DEADBEEF    │  0x00000000  │  0x00000003  │  0x000F  │ "The quick brow"   │
  │      u64         │      u32     │      u32     │   u16    │     15 bytes       │
  └──────────────────┴──────────────┴──────────────┴──────────┴────────────────────┘
  Header: 18 bytes, Data: 15 bytes = 33 bytes plaintext

Fragment 1:
  ┌──────────────────┬──────────────┬──────────────┬──────────┬────────────────────┐
  │  0x00DEADBEEF    │  0x00000001  │  0x00000003  │  0x000F  │ "n fox jumps ov"   │
  │      u64         │      u32     │      u32     │   u16    │     15 bytes       │
  └──────────────────┴──────────────┴──────────────┴──────────┴────────────────────┘
  Header: 18 bytes, Data: 15 bytes = 33 bytes plaintext

Fragment 2:
  ┌──────────────────┬──────────────┬──────────────┬──────────┬────────────────────┐
  │  0x00DEADBEEF    │  0x00000002  │  0x00000003  │  0x000E  │ "er the lazy dog"  │
  │      u64         │      u32     │      u32     │   u16    │     14 bytes       │
  └──────────────────┴──────────────┴──────────────┴──────────┴────────────────────┘
  Header: 18 bytes, Data: 14 bytes = 32 bytes plaintext


Each fragment is independently:
  → Encrypted with SealedBox (adds 48 bytes overhead: ~33 + 48 = ~81 bytes)
  → Base32 encoded (~81 bytes → ~130 chars)
  → Split into DNS labels (130 chars = 3 labels: 63 + 63 + 4 chars)
  → Domain added


THREE DNS QUERIES GENERATED:
────────────────────────────
Query 1: <63-char-label1>.<63-char-label2>.<4-char-label3>.asd.qwe
Query 2: <63-char-label1>.<63-char-label2>.<4-char-label3>.asd.qwe
Query 3: <63-char-label1>.<63-char-label2>.<2-char-label3>.asd.qwe


SERVER SIDE RECEIVES QUERIES OUT OF ORDER:
──────────────────────────────────────────

T=0  Query 3 arrives (Fragment 2):
     ├─ Decode, decrypt, parse: packet_id=0x00DEADBEEF, index=2, count=3
     ├─ Create: packet_assembly[0x00DEADBEEF] = [None, None, "er the lazy dog"]
     └─ Set: counter[0x00DEADBEEF] = 2

T=1  Query 1 arrives (Fragment 0):
     ├─ Decode, decrypt, parse: packet_id=0x00DEADBEEF, index=0, count=3
     ├─ Update: packet_assembly[0x00DEADBEEF] = ["The quick brow", None, "er the lazy dog"]
     └─ Decrement: counter[0x00DEADBEEF] = 1

T=2  Query 2 arrives (Fragment 1):
     ├─ Decode, decrypt, parse: packet_id=0x00DEADBEEF, index=1, count=3
     ├─ Update: packet_assembly[0x00DEADBEEF] = ["The quick brow", "n fox jumps ov", "er the lazy dog"]
     ├─ Decrement: counter[0x00DEADBEEF] = 0
     └─ COMPLETE! All fragments received.

     Reassemble:
     ┌────────────────┬────────────────┬────────────────┐
     │"The quick brow"│"n fox jumps ov"│"er the lazy dog"│
     └────────────────┴────────────────┴────────────────┘
                            ↓
     "The quick brown fox jumps over the lazy dog"

     Forward to output → Print or email
```

---

## Implementation Classes

### Class Hierarchy

```
BaseFragment
    │
    ├─→ Fragment
    │       │
    │       └─→ PublicFragment (adds NaCl encryption)
    │               │
    │               └─→ DnsPublicFragment (adds DNS encoding)
    │
PacketEngine (fragment/reassembly orchestration)
    │
DnsQueryReader (packet capture with tshark)
    │
SMTPForwarder (optional output)
```

### Key Methods

```python
# Fragment serialization
fragment.serialize() → bytes or str (DNS name)
fragment.deserialize(wire_data) → Fragment

# Packet engine
engine.to_wire(packet_data) → yields serialized fragments
engine.from_wire(wire_data) → reassembles, puts to queue

# DNS capture
for dns_name in DnsQueryReader(interface='en0', domain='.asd.qwe'):
    engine.from_wire(dns_name)
```

---

## Configuration

### Server Configuration File

```ini
[main]
# Domain for DNS queries (must include leading dot)
domain = .asd.qwe

# Network interface to monitor
# macOS: en0, en1, en2
# Linux: eth0, wlan0, ens33
network-interface = en0

# Base64-encoded NaCl keypair for server (mumbojumbo keys)
mumbojumbo-server-key = xQ9sAa...0N5K=
mumbojumbo-client-key = wP8rZX...Yz4M=

[smtp]
# Optional: forward received messages via email
server = smtp.gmail.com
port = 587
start-tls
username = sender@example.com
password = your-smtp-password
from = sender@example.com
to = recipient@example.com
```

### Key Generation

```bash
# Option 1: Generate environment variables (recommended)
$ ./mumbojumbo.py --gen-keys > ~/.mumbojumbo_env
$ source ~/.mumbojumbo_env

# Output:
# export MUMBOJUMBO_SERVER_KEY=mj_srv_<64_hex_chars>  # Server private key
# export MUMBOJUMBO_CLIENT_KEY=mj_cli_<64_hex_chars>  # Client public key (use with -k)
# export MUMBOJUMBO_DOMAIN=.xxxx.yyyy                # Domain for both server and client

# Option 2: Generate configuration file
$ ./mumbojumbo.py --gen-conf > mumbojumbo.conf
$ chmod 600 mumbojumbo.conf

# The config file contains comments showing which keys to give to client:
#   mumbojumbo_client_key = mj_cli_<64_hex_chars>
#   domain = .asd.qwe
```

### Key Format

Keys are hex-encoded (64 hex characters = 32 bytes) with prefixes:
- **Server key:** `mj_srv_<64_hex_chars>` - Server's private key (keep secret!)
- **Client key:** `mj_cli_<64_hex_chars>` - Server's public key (safe to share with clients)

Example:
```
mj_srv_f24d8109d69ffc89c688ffd069715691b8c1c583faeda28dfab9a1a092785d8c
mj_cli_6eaa1b50a62694a695c605b7491eb5cf87f1b210284b52cc5c99b3f3e2176048
```

### Client Configuration

Client needs:
1. `mumbojumbo_client_key` - Server's public key in hex format: `mj_cli_<64_hex_chars>`
2. `domain` - Domain suffix (e.g., `.asd.qwe`)

These can be:
- Passed via command line: `-k mj_cli_... -d .asd.qwe`
- Loaded from environment: `$MUMBOJUMBO_CLIENT_KEY $MUMBOJUMBO_DOMAIN`
- Hardcoded in client application

---

## Security Considerations

### Current Security Properties

✅ **Provides:**
- Confidentiality (encryption via NaCl SealedBox)
- Anonymity (no client authentication - sender is anonymous)
- Integrity (tampering detected during decryption)
- Covert channel (DNS queries appear innocuous)
- Simplicity (client only needs public key)

❌ **Does NOT Provide:**
- **Replay protection:** Attackers can capture and resend old fragments
- **Timestamp validation:** No guarantee of message freshness
- **Forward secrecy:** Compromised keys expose all past messages
- **Rate limiting:** Susceptible to resource exhaustion attacks
- **Fragment timeout:** Incomplete messages held in memory indefinitely
- **Sender anonymity:** Network-level analysis can identify client

### Attack Vectors

1. **Replay Attack:**
   - Attacker captures encrypted DNS queries
   - Resends them later → Server processes again
   - **Mitigation:** Add timestamps and nonces to message layer

2. **Resource Exhaustion:**
   - Attacker sends many incomplete messages
   - Server accumulates partial fragments in memory
   - **Mitigation:** Add timeouts and maximum message limits

3. **Traffic Analysis:**
   - Even though content is encrypted, DNS query patterns reveal:
     - Communication timing
     - Message sizes (number of queries)
     - Sender/receiver identity (network location)
   - **Mitigation:** Add cover traffic, timing obfuscation

4. **DNS Filtering:**
   - Organizations may block queries to unusual domains
   - Rate limiting on DNS servers
   - **Mitigation:** Use legitimate-looking domains, vary query patterns

### Recommended Improvements for Production

```python
# Add timestamp and sequence number to prevent replay
fragment_data = {
    'timestamp': int(time.time()),
    'sequence': sequence_counter,
    'payload': message_data
}

# Add perfect forward secrecy with ephemeral keys
ephemeral_key = nacl.public.PrivateKey.generate()
# Use DH key exchange per session

# Add fragment timeout
MAX_FRAGMENT_AGE = 300  # 5 minutes
if time.time() - fragment_timestamp > MAX_FRAGMENT_AGE:
    discard_fragment()

# Add message size limits
MAX_MESSAGE_SIZE = 1024 * 1024  # 1 MB
MAX_FRAGMENTS_PER_MESSAGE = 1000
```

---

## Performance Characteristics

### Overhead Analysis

```
Original Message: N bytes

Fragmentation:
  ├─ Header per fragment: 18 bytes (u64 + u32 + u32 + u16)
  ├─ Fragments: ceil(N / 80)
  └─ Total fragment headers: ceil(N / 80) × 18 bytes

Encryption (per fragment - SealedBox):
  ├─ Ephemeral public key: 32 bytes
  ├─ Authentication tag: 16 bytes
  └─ Overhead: 48 bytes per fragment

Base32 Encoding:
  ├─ Expansion: 1.6× (8 bytes → ~13 chars)
  └─ (Reversible)

DNS:
  ├─ Label separators: variable (depends on label count)
  ├─ Domain suffix: len(".asd.qwe") = 9 bytes
  └─ Maximum domain name: 253 characters

Total Overhead (approximate):
  Per fragment: 12 (header) + 48 (crypto) = 60 bytes constant
  Plus: 1.6× expansion from base32
  Plus: DNS overhead (~10-20 bytes)

  For 1 KB message (1024 bytes):
    ├─ Fragments: ceil(1024/80) = 13 fragments
    ├─ Fragment overhead: 13 × 60 = 780 bytes
    ├─ Base32 expansion: (1024 + 780) × 1.6 = 2886 bytes
    ├─ DNS overhead: 13 × 15 ≈ 195 bytes
    └─ Total transmitted: ~3081 bytes

  Overhead ratio: 3081 / 1024 = 3.01× (201% overhead)

  For 10 GB message (10,737,418,240 bytes):
    ├─ Fragments: ceil(10737418240/80) = 134,217,728 fragments
    ├─ Fragment overhead: 134,217,728 × 60 = 8,053,063,680 bytes (~8 GB)
    ├─ Base32 expansion: (10,737,418,240 + 8,053,063,680) × 1.6 = 30,064,770,672 bytes
    ├─ DNS overhead: 134,217,728 × 15 ≈ 2,013,265,920 bytes (~2 GB)
    └─ Total transmitted: ~32 GB

  10 GB overhead ratio: ~3.2× (220% overhead for large transfers)
```

### Throughput Limitations

DNS-based communication is inherently slow:

```
Typical DNS query time: 10-100ms
Maximum queries per second: 10-100 QPS (depending on resolver)

For 1 KB message requiring 13 fragments:
  Optimistic (10ms/query): 13 × 10ms = 130ms → 7.7 KB/s
  Pessimistic (100ms/query): 13 × 100ms = 1300ms → 0.77 KB/s

Compare to direct TCP: ~1-100 MB/s (1000-100000× faster)
```

**Conclusion:** Mumbojumbo prioritizes covertness over speed.

---

## Usage Examples

### Server Setup

**Option A: Using environment variables (recommended)**
```bash
# 1. Generate keys
$ ./mumbojumbo.py --gen-keys > ~/.mumbojumbo_env
$ source ~/.mumbojumbo_env

# 2. Start server (sudo -E preserves environment variables)
$ sudo -E ./mumbojumbo.py
```

**Option B: Using config file**
```bash
# 1. Generate config
$ ./mumbojumbo.py --gen-conf > mumbojumbo.conf
$ chmod 600 mumbojumbo.conf

# 2. Edit config (set network interface, domain, handlers)
$ nano mumbojumbo.conf

# 3. Test handlers (optional)
$ ./mumbojumbo.py --config mumbojumbo.conf --test-handlers

# 4. Start server (requires root for packet capture)
$ sudo ./mumbojumbo.py --config mumbojumbo.conf
```

**Option C: Using CLI overrides**
```bash
# Override configuration with command-line arguments
$ sudo ./mumbojumbo.py -k mj_srv_<64_hex> -d .example.com
```

**Configuration precedence:** CLI args > Environment variables > Config file

### Client (Python)

```python
# Using the Python client from clients/python/

# Option 1: With environment variables (recommended - no args needed!)
# source ~/.mumbojumbo_env
# echo "Hello" | ./clients/python/mumbojumbo-client.py

# Option 2: Via command line arguments
# echo "Hello" | ./clients/python/mumbojumbo-client.py \
#   -k mj_cli_f9ab4ab60d628f0a19e43592dfe078e16bbd37fa526ffef850411dad5e838c5e \
#   -d .asd.qwe

# Option 3: Programmatic usage
import sys
sys.path.insert(0, 'clients/python')
from mumbojumbo_client import parse_key_hex, MumbojumboClient

# Parse server public key (mj_cli_ format)
server_key = parse_key_hex('mj_cli_f9ab4ab60d628f0a19e43592dfe078e16bbd37fa526ffef850411dad5e838c5e')

# Create client
client = MumbojumboClient(server_key, '.asd.qwe')

# Send message
message = b"Hello from Mumbojumbo!"
queries = client.generate_queries(message)
for query in queries:
    print(f"Query: {query}")
    # In real use: send DNS query via dig or resolver library
```

**Client Configuration Precedence:** CLI arguments > Environment variables

### Client (HTML/JavaScript)

See [client.html](client.html) for a complete browser-based implementation.

```javascript
// Generate DNS queries in browser using SealedBox
const message = "Hello World!";
const queries = generateDnsQueries(message, mumbojumboPubKey, domain);
queries.forEach(query => {
    console.log(`Query: ${query}`);
    // DNS queries shown in console
    // In real use, configure browser DNS or use external tool
});
```

---

## Troubleshooting

### Common Issues

**Problem:** `tshark: command not found`
```bash
# macOS
$ brew install wireshark

# Linux
$ sudo apt-get install tshark
```

**Problem:** Permission denied when capturing packets
```bash
# Option 1: Run with sudo
$ sudo ./mumbojumbo.py --config mumbojumbo.conf

# Option 2: Grant capture capabilities (Linux)
$ sudo setcap cap_net_raw,cap_net_admin=eip /usr/bin/tshark
```

**Problem:** Network interface not found
```bash
# List interfaces
$ ip link show    # Linux
$ ifconfig        # macOS

# Update mumbojumbo.conf with correct interface name
network-interface = en0  # or eth0, wlan0, etc.
```

**Problem:** Decryption fails
- Verify client is using the correct mumbojumbo public key
- Check that `mumbojumbo-client-key` in server config matches the key given to client
- Ensure server has the correct `mumbojumbo-server-key` to decrypt

**Problem:** No queries captured
- Ensure server is listening on correct network interface
- Verify DNS queries are being sent to a resolver
- Check firewall rules (allow UDP port 53)
- Try sending query manually: `dig @8.8.8.8 test.asd.qwe`

---

## Protocol Comparison

### Mumbojumbo vs. Other Covert Channels

| Feature | Mumbojumbo | Iodine | Dnscat2 | ICMP Tunnel |
|---------|------------|---------|---------|-------------|
| **Transport** | DNS queries | DNS NULL records | DNS queries | ICMP Echo |
| **Encryption** | NaCl SealedBox | Optional | Optional | None |
| **Bi-directional** | No (one-way) | Yes | Yes | Yes |
| **Fragmentation** | Yes | Yes | Yes | Yes |
| **Authentication** | No (anonymous) | Password | Pre-shared key | None |
| **Setup complexity** | Low | Medium | Medium | Low |
| **Detection difficulty** | Medium | Medium | Medium | High |
| **Throughput** | Low | Low | Low | Medium |

---

## Future Enhancements

Potential improvements (see TODO in source code):

1. **Dynamic fragment sizing:** Adjust based on domain name length
2. **Distributed transmission:** Split key using Shamir's Secret Sharing, send across multiple domains
3. **Bidirectional communication:** Server responds to DNS queries with TXT records
4. **Multiple recipients:** Broadcast to multiple SMTP addresses
5. **Pluggable forwarders:** Generic interface for custom output handlers
6. **Fragment timeouts:** Garbage collect incomplete messages
7. **Replay protection:** Add timestamps and sequence numbers
8. **Forward secrecy:** Implement ephemeral key exchange

---

## References

### Cryptography
- **NaCl (Networking and Cryptography library):** https://nacl.cr.yp.to/
- **PyNaCl:** https://pynacl.readthedocs.io/
- **Curve25519:** https://cr.yp.to/ecdh.html
- **RFC 7748:** Elliptic Curves for Security

### DNS
- **RFC 1035:** Domain Names - Implementation and Specification
- **RFC 4648:** The Base16, Base32, and Base64 Data Encodings
- **DNS Tunneling:** https://en.wikipedia.org/wiki/DNS_tunneling

### Related Tools
- **Iodine:** https://code.kryo.se/iodine/
- **Dnscat2:** https://github.com/iagox86/dnscat2
- **tshark:** https://www.wireshark.org/docs/man-pages/tshark.html

---

## License

See source code for full license (BSD 2-Clause).

---

## Disclaimer

⚠️ **FOR EDUCATIONAL AND AUTHORIZED TESTING ONLY**

This protocol implementation is provided for:
- Educational purposes
- Authorized security testing
- CTF competitions
- Research with permission

**Do not use Mumbojumbo for:**
- Bypassing security controls without authorization
- Transmitting sensitive data in production
- Violating network usage policies
- Any illegal activities

The authors assume no liability for misuse of this software.

---

**ASCII Art Summary:**

```
     __  ___                __          _____              __
    /  |/  /_  ______ ___  / /_  ____  / /  ____  ______ ___  / /_  ____
   / /|_/ / / / / __ `__ \/ __ \/ __ \/ /  / __ \/ / __ `__ \/ __ \/ __ \
  / /  / / /_/ / / / / / / /_/ / /_/ / /  / /_/ / / / / / / / /_/ / /_/ /
 /_/  /_/\__,_/_/ /_/ /_/_.___/\____/_/   \____/_/_/ /_/ /_/_.___/\____/

    🔐 Encrypted DNS Tunneling Protocol 🔐

    Client ──[DNS Query]──> Infrastructure ──[Packet Sniff]──> Server
         (NaCl SealedBox)                                     (Decrypt)
            (Base32)                                          (Reassemble)
            (Fragment)                                        (Forward)
```

---

*End of Protocol Specification*
