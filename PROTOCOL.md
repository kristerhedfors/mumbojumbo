# Mumbojumbo Protocol Specification

## Overview

Mumbojumbo is a DNS tunneling protocol that provides covert, encrypted communication over DNS queries. It uses NaCl (libsodium) public key cryptography to encrypt messages, fragments them into manageable chunks, encodes them as base32, and transmits them as DNS subdomain queries.

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
│  │  Step 1: Fragment Message (80 bytes per fragment)           │   │
│  │                                                               │   │
│  │  Fragment 0: packet_id=0xABCD1234, index=0, count=3         │   │
│  │  Fragment 1: packet_id=0xABCD1234, index=1, count=3         │   │
│  │  Fragment 2: packet_id=0xABCD1234, index=2, count=3         │   │
│  └─────────────────────────────────────────────────────────────┘   │
│           │                                                           │
│           ▼                                                           │
│  ┌─────────────────────────────────────────────────────────────┐   │
│  │  Step 2: Encrypt each fragment with NaCl Box               │   │
│  │  (Client Private Key + Server Public Key)                   │   │
│  │                                                               │   │
│  │  Nonce (24 bytes) + Encrypted Payload (variable)            │   │
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
│  │  4qd7...xyz.abc1...def2.gh34...jkl5.xyxyx.xy                │   │
│  └─────────────────────────────────────────────────────────────┘   │
│           │                                                           │
│           ▼                                                           │
│  DNS Query: 4qd7...xyz.abc1...def2.gh34...jkl5.xyxyx.xy            │
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
│  │  Step 2: Filter by Domain (.xyxyx.xy)                       │   │
│  └─────────────────────────────────────────────────────────────┘   │
│           │                                                           │
│           ▼                                                           │
│  ┌─────────────────────────────────────────────────────────────┐   │
│  │  Step 3: Base32 Decode (remove labels, add padding)         │   │
│  └─────────────────────────────────────────────────────────────┘   │
│           │                                                           │
│           ▼                                                           │
│  ┌─────────────────────────────────────────────────────────────┐   │
│  │  Step 4: Decrypt with NaCl Box                              │   │
│  │  (Server Private Key + Client Public Key)                   │   │
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

## Binary Packet Format

### Fragment Structure

Each fragment consists of a header followed by payload data:

```
 0                   1                   2                   3
 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
┌───────────────────────────────────────────────────────────────┐
│                        Packet ID (u32)                        │
│                      (Network Byte Order)                     │
├───────────────────────────────────┬───────────────────────────┤
│      Fragment Index (u16)         │     Fragment Count (u16)  │
│    (Network Byte Order)           │   (Network Byte Order)    │
├───────────────────────────────────┴───────────────────────────┤
│          Fragment Data Length (u16)                           │
│              (Network Byte Order)                             │
├───────────────────────────────────────────────────────────────┤
│                                                               │
│                    Fragment Data (variable)                   │
│                                                               │
│                         (0-80 bytes)                          │
│                                                               │
└───────────────────────────────────────────────────────────────┘

Total Header Size: 10 bytes
Max Fragment Data: 80 bytes (configurable)
Max Fragment Size: 90 bytes
```

### Field Descriptions

| Field | Size | Type | Description |
|-------|------|------|-------------|
| **Packet ID** | 4 bytes | u32 (big-endian) | Unique identifier for the complete message. All fragments of the same message share this ID. Generated from 4 random bytes. |
| **Fragment Index** | 2 bytes | u16 (big-endian) | Zero-based index of this fragment (0 to count-1). Used for ordering during reassembly. |
| **Fragment Count** | 2 bytes | u16 (big-endian) | Total number of fragments in this message. Same for all fragments with matching Packet ID. |
| **Data Length** | 2 bytes | u16 (big-endian) | Length of the fragment data field. Must match actual data length. |
| **Fragment Data** | variable | bytes | Raw message payload for this fragment. Maximum 80 bytes (default). |

---

## Encryption Layer

Mumbojumbo uses NaCl (libsodium) public-key authenticated encryption via `nacl.public.Box`.

### Key Exchange

```
┌──────────────────────────────────────────────────────────────┐
│                  Key Generation & Exchange                    │
├──────────────────────────────────────────────────────────────┤
│                                                               │
│  Server Side:                                                 │
│  ┌────────────────────────────────────────────────────────┐ │
│  │ $ ./mumbojumbo.py --generate-conf > mumbojumbo.conf   │ │
│  │                                                          │ │
│  │ Generates:                                               │ │
│  │   • Server Private Key (32 bytes)                       │ │
│  │   • Server Public Key (32 bytes)                        │ │
│  │   • Client Private Key (32 bytes)                       │ │
│  │   • Client Public Key (32 bytes)                        │ │
│  │                                                          │ │
│  │ Server stores:  server_privkey, client_pubkey          │ │
│  │ Client receives: client_privkey, server_pubkey          │ │
│  └────────────────────────────────────────────────────────┘ │
│                                                               │
│  Configuration File (mumbojumbo.conf):                        │
│  ┌────────────────────────────────────────────────────────┐ │
│  │ [main]                                                   │ │
│  │ domain = .xyxyx.xy                                       │ │
│  │ network-interface = en0                                  │ │
│  │ client-pubkey = wP8r...M= (base64)                       │ │
│  │ server-privkey = xQ9s...N= (base64)                      │ │
│  └────────────────────────────────────────────────────────┘ │
│                                                               │
│  Out-of-Band Transfer:                                        │
│  ┌────────────────────────────────────────────────────────┐ │
│  │ Client receives via secure channel:                     │ │
│  │   • client_privkey = yR0t...O= (base64)                 │ │
│  │   • server_pubkey = zS1u...P= (base64)                  │ │
│  │   • domain = .xyxyx.xy                                   │ │
│  └────────────────────────────────────────────────────────┘ │
│                                                               │
└──────────────────────────────────────────────────────────────┘
```

### Encryption Process

Each fragment undergoes the following encryption:

```python
# Client Side (Transmission)
plaintext = serialize_fragment(packet_id, frag_index, frag_count, data)
nonce = random_bytes(24)  # New random nonce per fragment
box = nacl.public.Box(client_private_key, server_public_key)
ciphertext = box.encrypt(plaintext, nonce)
# ciphertext = nonce (24 bytes) + encrypted_data (variable)

# Server Side (Reception)
box = nacl.public.Box(server_private_key, client_public_key)
plaintext = box.decrypt(ciphertext)  # Nonce is extracted automatically
fragment = parse_fragment(plaintext)
```

**Security Properties:**
- **Authentication:** Server can verify the message came from the legitimate client
- **Confidentiality:** Only the server with the private key can decrypt messages
- **Integrity:** Any tampering is detected during decryption

**Limitations:**
- ⚠️ **No replay protection:** Old messages can be replayed
- ⚠️ **No forward secrecy:** Compromised keys expose all past messages
- ⚠️ **No timestamp validation:** Messages can be delayed or reordered

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
│  │    jjvruxg4bfjrq2lbmfxgs43pn5tuk6bqmfzwk.xyxyx.xy       │ │
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
│  │    <label1>.<label2>.<label3>.xyxyx.xy                  │ │
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
dns_name = ".".join(labels) + ".xyxyx.xy"
# Result: "jjvruxg4bfjrq2lbmfxgs43pn5tuk6bq.xyxyx.xy"

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
   Packet ID: 0x12345678
   Fragment 0/1 (only one fragment needed)
   ┌─────────────┬──────────┬──────────┬──────────┬──────┐
   │ 0x12345678  │   0x0000 │   0x0001 │   0x0002 │  HI  │
   │ (packet_id) │  (index) │  (count) │  (len)   │(data)│
   └─────────────┴──────────┴──────────┴──────────┴──────┘
   10 bytes header + 2 bytes data = 12 bytes plaintext

3. Encrypt with NaCl Box:
   Nonce: [24 random bytes]
   Plaintext: 12 bytes
   Ciphertext: 24 + 28 = 52 bytes (nonce + encrypted + auth tag)

4. Base32 Encode:
   52 bytes → 84 characters (base32)
   Result: "eizuwyzblbqwy3dfon2gs3thebswy3lpnyqhmzlsoqydamb3he2dkmztge3dsmrsmfzwizlsfy"

5. Create DNS query:
   (84 chars, fits in one label)
   DNS: eizuwyzblbqwy3dfon2gs3thebswy3lpnyqhmzlsoqydamb3he2dkmztge3dsmrsmfzwizlsfy.xyxyx.xy

6. Send DNS query to resolver


DNS INFRASTRUCTURE:
──────────────────
Query propagates through DNS system
Recursive resolvers attempt to resolve .xyxyx.xy domain
Eventually reaches authoritative servers (or fails)
Server captures query via packet sniffing (tshark)


SERVER SIDE:
───────────
1. tshark captures:
   "eizuwyzblbqwy3dfon2gs3thebswy3lpnyqhmzlsoqydamb3he2dkmztge3dsmrsmfzwizlsfy.xyxyx.xy"

2. Filter: ends with ".xyxyx.xy" ✓

3. Base32 Decode:
   Remove domain: "eizuwyzblbqwy3dfon2gs3thebswy3lpnyqhmzlsoqydamb3he2dkmztge3dsmrsmfzwizlsfy"
   Decode: 84 chars → 52 bytes

4. Decrypt with NaCl Box:
   Extract nonce (24 bytes)
   Decrypt remaining 28 bytes
   Result: 12 bytes plaintext

5. Parse Fragment:
   packet_id: 0x12345678
   frag_index: 0
   frag_count: 1
   frag_data_len: 2
   frag_data: "HI"

6. Reassemble:
   Only 1 fragment → immediately complete
   counter[0x12345678] = 1 - 1 = 0 ✓

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
Packet ID: 0xDEADBEEF (randomly generated)

Fragment 0:
  ┌─────────────┬──────────┬──────────┬──────────┬────────────────────┐
  │ 0xDEADBEEF  │   0x0000 │   0x0003 │   0x000F │ "The quick brow"   │
  └─────────────┴──────────┴──────────┴──────────┴────────────────────┘
  Header: 10 bytes, Data: 15 bytes = 25 bytes plaintext

Fragment 1:
  ┌─────────────┬──────────┬──────────┬──────────┬────────────────────┐
  │ 0xDEADBEEF  │   0x0001 │   0x0003 │   0x000F │ "n fox jumps ov"   │
  └─────────────┴──────────┴──────────┴──────────┴────────────────────┘
  Header: 10 bytes, Data: 15 bytes = 25 bytes plaintext

Fragment 2:
  ┌─────────────┬──────────┬──────────┬──────────┬────────────────────┐
  │ 0xDEADBEEF  │   0x0002 │   0x0003 │   0x000E │ "er the lazy dog"  │
  └─────────────┴──────────┴──────────┴──────────┴────────────────────┘
  Header: 10 bytes, Data: 14 bytes = 24 bytes plaintext


Each fragment is independently:
  → Encrypted (adds nonce + auth tag: ~25 + 40 = ~65 bytes)
  → Base32 encoded (~65 bytes → ~104 chars)
  → Split into DNS labels (104 chars = 2 labels of 52 chars each)
  → Domain added


THREE DNS QUERIES GENERATED:
────────────────────────────
Query 1: <104-char-base32-label1>.<52-char-remainder>.xyxyx.xy
Query 2: <104-char-base32-label1>.<52-char-remainder>.xyxyx.xy
Query 3: <100-char-base32-label1>.<50-char-remainder>.xyxyx.xy


SERVER SIDE RECEIVES QUERIES OUT OF ORDER:
──────────────────────────────────────────

T=0  Query 3 arrives (Fragment 2):
     ├─ Decode, decrypt, parse: packet_id=0xDEADBEEF, index=2, count=3
     ├─ Create: packet_assembly[0xDEADBEEF] = [None, None, "er the lazy dog"]
     └─ Set: counter[0xDEADBEEF] = 2

T=1  Query 1 arrives (Fragment 0):
     ├─ Decode, decrypt, parse: packet_id=0xDEADBEEF, index=0, count=3
     ├─ Update: packet_assembly[0xDEADBEEF] = ["The quick brow", None, "er the lazy dog"]
     └─ Decrement: counter[0xDEADBEEF] = 1

T=2  Query 2 arrives (Fragment 1):
     ├─ Decode, decrypt, parse: packet_id=0xDEADBEEF, index=1, count=3
     ├─ Update: packet_assembly[0xDEADBEEF] = ["The quick brow", "n fox jumps ov", "er the lazy dog"]
     ├─ Decrement: counter[0xDEADBEEF] = 0
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
for dns_name in DnsQueryReader(interface='en0', domain='.xyxyx.xy'):
    engine.from_wire(dns_name)
```

---

## Configuration

### Server Configuration File

```ini
[main]
# Domain for DNS queries (must include leading dot)
domain = .xyxyx.xy

# Network interface to monitor
# macOS: en0, en1, en2
# Linux: eth0, wlan0, ens33
network-interface = en0

# Base64-encoded NaCl public key from client
client-pubkey = wP8rZX...Yz4M=

# Base64-encoded NaCl private key for server
server-privkey = xQ9sAa...0N5K=

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
# Generate configuration with fresh keys
$ ./mumbojumbo.py --generate-conf > mumbojumbo.conf
$ chmod 600 mumbojumbo.conf

# The config file contains comments showing which keys to give to client:
#   client_privkey=<key1>
#   server_pubkey=<key2>
```

### Client Configuration

Client needs:
1. `client_privkey` (32 bytes, base64)
2. `server_pubkey` (32 bytes, base64)
3. `domain` (e.g., `.xyxyx.xy`)

These can be hardcoded in client application or loaded from config.

---

## Security Considerations

### Current Security Properties

✅ **Provides:**
- Confidentiality (encryption via NaCl Box)
- Authentication (client cannot be impersonated without private key)
- Integrity (tampering detected during decryption)
- Covert channel (DNS queries appear innocuous)

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
  ├─ Header per fragment: 10 bytes
  ├─ Fragments: ceil(N / 80)
  └─ Total fragment headers: ceil(N / 80) × 10 bytes

Encryption (per fragment):
  ├─ Nonce: 24 bytes
  ├─ Authentication tag: 16 bytes
  └─ Overhead: 40 bytes per fragment

Base32 Encoding:
  ├─ Expansion: 1.6× (8 bytes → ~13 chars)
  └─ (Reversible)

DNS:
  ├─ Label separators: variable (depends on label count)
  ├─ Domain suffix: len(".xyxyx.xy") = 9 bytes
  └─ Maximum domain name: 253 characters

Total Overhead (approximate):
  Per fragment: 10 (header) + 40 (crypto) = 50 bytes constant
  Plus: 1.6× expansion from base32
  Plus: DNS overhead (~10-20 bytes)

  For 1 KB message (1024 bytes):
    ├─ Fragments: ceil(1024/80) = 13 fragments
    ├─ Fragment overhead: 13 × 50 = 650 bytes
    ├─ Base32 expansion: (1024 + 650) × 1.6 = 2678 bytes
    ├─ DNS overhead: 13 × 15 ≈ 195 bytes
    └─ Total transmitted: ~2873 bytes

  Overhead ratio: 2873 / 1024 = 2.8× (180% overhead)
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

```bash
# 1. Generate config
$ ./mumbojumbo.py --generate-conf > mumbojumbo.conf
$ chmod 600 mumbojumbo.conf

# 2. Edit config (set network interface, domain, SMTP if desired)
$ nano mumbojumbo.conf

# 3. Test SMTP (optional)
$ ./mumbojumbo.py --config mumbojumbo.conf --test-smtp

# 4. Start server (requires root for packet capture)
$ sudo ./mumbojumbo.py --config mumbojumbo.conf
```

### Client (Python)

```python
import base64
import nacl.public

# Configuration from server
CLIENT_PRIVKEY = base64.b64decode('yR0t...O=')
SERVER_PUBKEY = base64.b64decode('zS1u...P=')
DOMAIN = '.xyxyx.xy'

# Create keys
client_private = nacl.public.PrivateKey(CLIENT_PRIVKEY)
server_public = nacl.public.PublicKey(SERVER_PUBKEY)

# Create fragment class
from mumbojumbo import DnsPublicFragment, PacketEngine

frag_cls = DnsPublicFragment.bind(
    domain=DOMAIN,
    private_key=client_private,
    public_key=server_public
)

# Create packet engine
engine = PacketEngine(frag_cls)

# Send message
message = b"Hello from Mumbojumbo!"
for dns_query in engine.to_wire(message):
    print(f"Query: {dns_query}")
    # In real use: send this DNS query via resolver
    # Example: subprocess.run(['dig', dns_query])
```

### Client (HTML/JavaScript)

See [client.html](client.html) for a complete browser-based implementation.

```javascript
// Generate DNS queries in browser
const message = "Hello World!";
const queries = generateDnsQueries(message, clientPrivKey, serverPubKey, domain);
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
- Verify client and server are using matching key pairs
- Check that `client_pubkey` on server matches `client_privkey` on client
- Check that `server_privkey` on server matches `server_pubkey` on client

**Problem:** No queries captured
- Ensure server is listening on correct network interface
- Verify DNS queries are being sent to a resolver
- Check firewall rules (allow UDP port 53)
- Try sending query manually: `dig @8.8.8.8 test.xyxyx.xy`

---

## Protocol Comparison

### Mumbojumbo vs. Other Covert Channels

| Feature | Mumbojumbo | Iodine | Dnscat2 | ICMP Tunnel |
|---------|------------|---------|---------|-------------|
| **Transport** | DNS queries | DNS NULL records | DNS queries | ICMP Echo |
| **Encryption** | NaCl public key | Optional | Optional | None |
| **Bi-directional** | No (one-way) | Yes | Yes | Yes |
| **Fragmentation** | Yes | Yes | Yes | Yes |
| **Authentication** | Yes (crypto) | Password | Pre-shared key | None |
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
            (NaCl Box)                                        (Decrypt)
            (Base32)                                          (Reassemble)
            (Fragment)                                        (Forward)
```

---

*End of Protocol Specification*
