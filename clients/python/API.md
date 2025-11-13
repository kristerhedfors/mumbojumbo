# Python Client API

## Programmatic Interface

The `MumbojumboClient` class provides a clean, modular interface for sending data via DNS queries.

### Basic Usage

```python
from mumbojumbo_client import MumbojumboClient, parse_key_hex

# Parse server public key
server_client_key = parse_key_hex('mj_cli_f9ab4ab60d628f0a19e43592dfe078e16bbd37fa526ffef850411dad5e838c5e')

# Initialize client
client = MumbojumboClient(server_client_key, '.asd.qwe')

# Send data
results = client.send_data(b"Hello World")

# Check results
for dns_query, success in results:
    print(f"{dns_query}: {'✓' if success else '✗'}")
```

### Generate Queries Without Sending

```python
# Just generate DNS queries without sending them
queries = client.generate_queries(b"Test data")

for query in queries:
    print(query)
    # Do something with the query (send via custom DNS resolver, log, etc.)
```

### API Reference

#### `MumbojumboClient(server_public_key, domain, max_fragment_size=80)`

Initialize a new client instance.

**Parameters:**
- `server_public_key`: Server's public key (bytes or `nacl.public.PublicKey`)
- `domain`: DNS domain suffix (e.g., `'.asd.qwe'`)
- `max_fragment_size`: Maximum bytes per fragment (default: 80)

**Features:**
- Automatic packet ID management (increments with each send)
- Auto-prepends dot to domain if missing
- Accepts public key as bytes or NaCl PublicKey object

#### `send_data(data)`

Send data via DNS queries.

**Parameters:**
- `data`: Bytes to send

**Returns:**
- `list`: List of `(dns_query, success)` tuples

**Example:**
```python
results = client.send_data(b"My message")

# Check if all fragments sent successfully
all_success = all(success for _, success in results)
print(f"All fragments sent: {all_success}")
```

#### `generate_queries(data)`

Generate DNS queries without sending them.

**Parameters:**
- `data`: Bytes to send

**Returns:**
- `list`: List of DNS query strings

**Example:**
```python
queries = client.generate_queries(b"Test")
print(f"Generated {len(queries)} queries")
```

### Helper Functions

#### `parse_key_hex(key_str)`

Parse a hex-encoded public key in `mj_cli_<hex>` format.

**Parameters:**
- `key_str`: Key string (e.g., `'mj_cli_abc123...'`)

**Returns:**
- `bytes`: 32-byte public key

**Raises:**
- `ValueError`: If key format is invalid

#### Low-Level Functions

The following functions are available for custom implementations:

- `create_fragment(packet_id, frag_index, frag_count, frag_data)` - Build fragment with 12-byte header
- `encrypt_fragment(plaintext, server_client_key)` - Encrypt with NaCl SealedBox
- `base32_encode(data)` - Base32 encode (lowercase, no padding)
- `split_to_labels(data, max_len=63)` - Split into DNS labels
- `create_dns_query(encrypted, domain)` - Create full DNS query name
- `send_dns_query(dns_name)` - Send query via `dig` command
- `fragment_data(data, max_fragment_size=80)` - Split data into chunks

## Example Scripts

### Send File Contents

```python
#!/usr/bin/env python3
from mumbojumbo_client import MumbojumboClient, parse_key_hex

# Configuration
SERVER_KEY = 'mj_cli_f9ab4ab60d628f0a19e43592dfe078e16bbd37fa526ffef850411dad5e838c5e'
DOMAIN = '.asd.qwe'

# Read file
with open('message.txt', 'rb') as f:
    data = f.read()

# Send via DNS
client = MumbojumboClient(parse_key_hex(SERVER_KEY), DOMAIN)
results = client.send_data(data)

# Report
success_count = sum(1 for _, success in results if success)
print(f"Sent {success_count}/{len(results)} fragments")
```

### Send Multiple Messages

```python
#!/usr/bin/env python3
from mumbojumbo_client import MumbojumboClient, parse_key_hex

SERVER_KEY = parse_key_hex('mj_cli_...')
client = MumbojumboClient(SERVER_KEY, '.asd.qwe')

messages = [
    b"First message",
    b"Second message",
    b"Third message"
]

for msg in messages:
    results = client.send_data(msg)
    success = all(s for _, s in results)
    print(f"Sent '{msg.decode()}': {'✓' if success else '✗'}")
```

### Custom DNS Sending

```python
#!/usr/bin/env python3
from mumbojumbo_client import MumbojumboClient, parse_key_hex
import dns.resolver  # dnspython library

SERVER_KEY = parse_key_hex('mj_cli_...')
client = MumbojumboClient(SERVER_KEY, '.asd.qwe')

# Generate queries without sending
queries = client.generate_queries(b"Test data")

# Send via custom DNS resolver
resolver = dns.resolver.Resolver()
resolver.nameservers = ['8.8.8.8']  # Google DNS

for query in queries:
    try:
        resolver.resolve(query, 'A')
        print(f"✓ {query}")
    except Exception as e:
        print(f"✗ {query}: {e}")
```

## Protocol Details

### Packet ID Management

- Each `MumbojumboClient` instance maintains an internal packet ID counter
- Starts at a random u64 value (0 to 2^64-1)
- Automatically increments with each `send_data()` or `generate_queries()` call
- Wraps around at 2^64-1 back to 0
- Completely internal - not exposed to users
- Thread-safe for single-client usage

### Fragment Structure

```
Bytes 0-7:   packet_id (u64 big-endian)
Bytes 8-11:  frag_index (u32 big-endian) - supports up to 4.3 billion fragments
Bytes 12-15: frag_count (u32 big-endian) - supports up to 4.3 billion fragments
Bytes 16-17: data_length (u16 big-endian)
Bytes 18+:   fragment data (max 80 bytes)

Total header: 18 bytes
```

### Protocol Capacity

- **Maximum fragments per packet:** 4,294,967,295 (2³² - 1)
- **Maximum packet size:** ~320 GB (343,597,383,600 bytes)
- **Fragment data:** 80 bytes per fragment
- **Practical use:** Easily supports multi-GB file transfers

### Encryption

- Uses NaCl SealedBox (X25519 + XSalsa20-Poly1305)
- Anonymous encryption (no client key pair needed)
- 48-byte overhead per fragment (ephemeral public key + auth tag)

### DNS Encoding

1. Encrypt fragment with SealedBox
2. Base32 encode (lowercase, no padding)
3. Split into 63-character labels
4. Join with dots and append domain

## CLI Interface

The module also provides a command-line interface:

```bash
# Send from stdin
echo "Hello" | ./mumbojumbo-client.py -k mj_cli_... -d .asd.qwe

# Send from file
./mumbojumbo-client.py -k mj_cli_... -d .asd.qwe -f message.txt

# Verbose mode
./mumbojumbo-client.py -k mj_cli_... -d .asd.qwe -v
```

See `README.md` for full CLI documentation.
