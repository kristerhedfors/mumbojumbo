# Python Client API

## Programmatic Interface

The `MumbojumboClient` class provides a clean, user-friendly interface for sending key-value pairs via DNS queries.

### Basic Usage

```python
from mumbojumbo_client import MumbojumboClient

# Initialize client (key parsing is automatic)
client = MumbojumboClient(
    server_client_key='mj_cli_f9ab4ab60d628f0a19e43592dfe078e16bbd37fa526ffef850411dad5e838c5e',
    domain='.example.com'
)

# Send key-value pair
results = client.send(b'filename.txt', b'Hello World')

# Check results
for dns_query, success in results:
    print(f"{dns_query}: {'✓' if success else '✗'}")
```

### Generate Queries Without Sending

```python
# Just generate DNS queries without sending them
queries = client.generate_queries(b'mykey', b'myvalue')

for query in queries:
    print(query)
    # Do something with the query (send via custom DNS resolver, log, etc.)
```

### API Reference

#### `MumbojumboClient(server_client_key, domain, max_fragment_size=None)`

Initialize a new client instance.

**Parameters:**
- `server_client_key`: Server's public key (accepts `mj_cli_<hex>` string, bytes, or `nacl.public.PublicKey`)
- `domain`: DNS domain suffix (e.g., `'.example.com'`)
- `max_fragment_size`: Maximum bytes per fragment (default: auto-calculated from domain)

**Features:**
- Automatic key parsing (handles `mj_cli_` hex format)
- Automatic packet ID management (cryptographically random, auto-increments)
- Auto-calculated fragment sizing based on domain length
- Auto-prepends dot to domain if missing
- Accepts public key as bytes or NaCl PublicKey object

#### `send(key, value)`

Send key-value pair via DNS queries.

**Parameters:**
- `key`: Key bytes or `None` (for null/zero-length key)
- `value`: Value bytes (MUST be at least 1 byte, cannot be `None` or empty)

**Returns:**
- `list`: List of `(dns_query, success)` tuples

**Example:**
```python
results = client.send(b'filename.txt', b'Hello, World!')

# Check if all fragments sent successfully
all_success = all(success for _, success in results)
print(f"All fragments sent: {all_success}")
```

#### `generate_queries(key, value)`

Generate DNS queries for key-value pair without sending them.

**Parameters:**
- `key`: Key bytes or `None` (for null/zero-length key)
- `value`: Value bytes (MUST be at least 1 byte, cannot be `None` or empty)

**Returns:**
- `list`: List of DNS query strings

**Example:**
```python
queries = client.generate_queries(b'mykey', b'myvalue')
print(f"Generated {len(queries)} queries")
```

### Low-Level Functions (Advanced)

The following functions are available for custom implementations or understanding internals:

- `create_fragment(packet_id, frag_index, frag_count, frag_data, key_len=0)` - Build fragment with 19-byte header
- `encrypt_fragment(plaintext, server_client_key)` - Encrypt with NaCl SealedBox
- `base32_encode(data)` - Base32 encode (lowercase, no padding)
- `split_to_labels(data, max_len=63)` - Split into DNS labels
- `create_dns_query(encrypted, domain)` - Create full DNS query name
- `send_dns_query(dns_name)` - Send query via `dig` command
- `fragment_data(data, max_fragment_size)` - Split data into chunks
- `calculate_safe_max_fragment_data_len(domain)` - Calculate safe max fragment size

**Note:** You typically don't need these functions - `MumbojumboClient` handles everything internally.

## Example Scripts

### Send File Contents

```python
#!/usr/bin/env python3
from mumbojumbo_client import MumbojumboClient

# Configuration
SERVER_KEY = 'mj_cli_f9ab4ab60d628f0a19e43592dfe078e16bbd37fa526ffef850411dad5e838c5e'
DOMAIN = '.example.com'

# Read file
with open('message.txt', 'rb') as f:
    file_data = f.read()

# Send via DNS with filename as key
client = MumbojumboClient(SERVER_KEY, DOMAIN)
results = client.send(b'message.txt', file_data)

# Report
success_count = sum(1 for _, success in results if success)
print(f"Sent {success_count}/{len(results)} fragments")
```

### Send Multiple Key-Value Pairs

```python
#!/usr/bin/env python3
from mumbojumbo_client import MumbojumboClient

client = MumbojumboClient('mj_cli_...', '.example.com')

# Send multiple key-value pairs
pairs = [
    (b'config.json', b'{"setting": "value"}'),
    (b'data.csv', b'col1,col2\n1,2'),
    (None, b'Anonymous message')  # None key = null/empty key
]

for key, value in pairs:
    results = client.send(key, value)
    success = all(s for _, s in results)
    key_display = key.decode() if key else 'None'
    print(f"Sent key='{key_display}': {'✓' if success else '✗'}")
```

### Custom DNS Sending

```python
#!/usr/bin/env python3
from mumbojumbo_client import MumbojumboClient
import dns.resolver  # dnspython library

client = MumbojumboClient('mj_cli_...', '.example.com')

# Generate queries without sending
queries = client.generate_queries(b'mykey', b'myvalue')

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
