# Mumbojumbo Python Client

Reference implementation of the mumbojumbo DNS protocol client in Python.

## Features

- **Minimalist design**: Only requires `pynacl` library
- **Key-value mode**: Send key-value pairs or files with filenames as keys
- **Auto-calculated fragment sizing**: Dynamically calculates safe fragment size based on domain length
- **Stdin/file input**: Read from stdin or multiple files
- **Multi-fragment support**: Automatically splits large messages
- **Verbose mode**: Debug output for troubleshooting
- **Environment variable support**: Configure via CLI args or env vars

## Installation

```bash
pip install pynacl
```

## Usage

### Basic Examples

```bash
# Option 1: Use environment variables (recommended)
export MUMBOJUMBO_CLIENT_KEY=mj_cli_f9ab4ab60d628f0a19e43592dfe078e16bbd37fa526ffef850411dad5e838c5e
export MUMBOJUMBO_DOMAIN=.asd.qwe

# Send from stdin with null key (key=None)
echo "Hello World" | ./mumbojumbo-client.py

# Send from stdin with custom key
echo "Hello World" | ./mumbojumbo-client.py -k mykey

# Option 2: Use command-line arguments
echo "Hello World" | ./mumbojumbo-client.py \
  --client-key mj_cli_f9ab4ab60d628f0a19e43592dfe078e16bbd37fa526ffef850411dad5e838c5e \
  -d .asd.qwe

# Send files (filename as key, contents as value)
./mumbojumbo-client.py file1.txt file2.txt

# Send explicit key-value pair
./mumbojumbo-client.py -k mykey -v myvalue

# Verbose mode for debugging
echo "test" | ./mumbojumbo-client.py --verbose
```

### Command Line Options

- `--client-key <public_key>` - Server public key in `mj_cli_<hex>` format (or use `MUMBOJUMBO_CLIENT_KEY` env var)
- `-d, --domain <domain>` - DNS domain suffix, e.g., `.asd.qwe` (or use `MUMBOJUMBO_DOMAIN` env var)
- `-k, --key <key>` - Transmission key (for stdin or with -v; NOT allowed with files where filename is key)
- `-v, --value <value>` - Transmission value (if not provided, reads from stdin or files)
- `--verbose` - Enable verbose output to stderr
- `files` - Files to send (filename as key, contents as value)

**Configuration Precedence:** CLI arguments > Environment variables

### Key-Value Mode

The client operates in **key-value mode**, where every transmission consists of:
- **Key**: Optional (can be `None` or empty), max 255 bytes
- **Value**: Required (must be at least 1 byte)

**Usage Modes:**

1. **Stdin with null key** (no `-k` flag):
   ```bash
   echo "data" | ./mumbojumbo-client.py  # key=None
   ```

2. **Stdin with custom key** (with `-k` flag):
   ```bash
   echo "data" | ./mumbojumbo-client.py -k mykey  # key="mykey"
   ```

3. **Explicit key-value** (both `-k` and `-v`):
   ```bash
   ./mumbojumbo-client.py -k mykey -v myvalue
   ```

4. **Files** (filename as key):
   ```bash
   ./mumbojumbo-client.py file.txt  # key="file.txt", value=<file contents>
   # Note: -k flag is NOT allowed with files
   ```

## Protocol Details

### Fragment Structure

Each message is split into dynamically-sized fragments with a **18-byte header**:

```
Bytes 0-7:   packet_id (u64 big-endian) - 64-bit packet ID
Bytes 8-11:  frag_index (u32 big-endian) - supports up to 4.3 billion fragments
Bytes 12-15: frag_count (u32 big-endian) - supports up to 4.3 billion fragments
Bytes 16:    frag_data_len (u8) - length of fragment data (0-255)
Bytes 17:    key_len (u8) - length of key in reassembled packet (0-255)
Bytes 18+:   fragment data (max 255 bytes, auto-calculated based on domain)
```

**Header Changes:**
- **18 bytes total** (was 12 bytes in older versions)
- Added `key_len` field for key-value mode support
- Changed `data_length` from u16 to u8 (fragment data limited to 0-255 bytes)

### Auto-Calculated Fragment Sizing

Fragment size is **automatically calculated** based on your domain length using the formula:

```
max_fragment_data_len = 83 - len(domain) // 3
```

**Examples:**
- Domain `.a.b` (4 chars) → 82 bytes per fragment
- Domain `.example.com` (12 chars) → 79 bytes per fragment
- Domain `.very-long-subdomain.example.com` (33 chars) → 72 bytes per fragment

This ensures DNS queries stay within the 253-character limit while maximizing throughput.

### Protocol Capacity

- **Maximum fragments per packet:** 4,294,967,295 (2³² - 1)
- **Maximum packet size:** ~1 TB (depending on fragment size)
- **Practical use:** Supports multi-GB file transfers over DNS

### Encryption

- Uses **NaCl SealedBox** for anonymous public-key encryption
- No client keypair needed
- Overhead: 48 bytes per fragment (ephemeral key + auth tag)

### DNS Encoding

1. Fragment encrypted with SealedBox
2. Encrypted data base32-encoded (lowercase, no padding)
3. Base32 string split into 63-character DNS labels
4. Labels joined with dots and domain appended

### Example Flow

```
Input: Key="file.txt" (8 bytes) + Value="Hello World" (11 bytes)
→ Combined: 19 bytes total
→ Fragment: 18-byte header + 19 bytes data = 37 bytes
→ Encrypt: 37 + 48 = 85 bytes (SealedBox overhead)
→ Base32: ~136 characters
→ DNS: <136-char-base32>.asd.qwe
```

## Programmatic API

```python
from mumbojumbo_client import MumbojumboClient

# Initialize client with mj_cli_ format key (auto-parsed)
# Fragment size is auto-calculated from domain
client = MumbojumboClient(
    'mj_cli_f9ab4ab60d628f0a19e43592dfe078e16bbd37fa526ffef850411dad5e838c5e',
    '.asd.qwe'
)

# Send key-value pair (actually sends DNS queries)
results = client.send_key_val(b'mykey', b'myvalue')
for dns_query, success in results:
    print(f"{dns_query}: {'✓' if success else '✗'}")

# Send with null key
results = client.send_key_val(None, b'data only')

# Or just generate queries without sending
queries = client.generate_queries_key_val(b'key', b'value')
for query in queries:
    print(query)
```

### API Reference

#### `MumbojumboClient(server_client_key, domain, max_fragment_size=None)`

Creates a new client instance.

**Parameters:**
- `server_client_key` - Server's public key (mj_cli_ hex string, bytes, or nacl.public.PublicKey)
- `domain` - DNS domain suffix (e.g., `.asd.qwe`)
- `max_fragment_size` - Maximum bytes per fragment (default: auto-calculated from domain using `calculate_safe_max_fragment_data_len()`)

**Features:**
- Auto-parses `mj_cli_<hex>` format keys
- Auto-prepends dot to domain if missing
- Auto-calculates safe fragment size based on domain length

#### `send_key_val(key, value)`

Send key-value pair via DNS queries.

**Parameters:**
- `key` - Key bytes or None (for null/zero-length key)
- `value` - Value bytes (MUST be at least 1 byte, cannot be None or empty)

**Returns:** List of `(dns_query, success)` tuples

**Validation:**
- `key` can be `None` or `b''` (both become zero-length key)
- `key` max length: 255 bytes
- `value` must be non-None and at least 1 byte

**Example:**
```python
# Send with key
results = client.send_key_val(b'filename.txt', b'file contents')

# Send with null key
results = client.send_key_val(None, b'anonymous data')

# Send with empty key (same as None)
results = client.send_key_val(b'', b'data')
```

#### `generate_queries_key_val(key, value)`

Generate key-value DNS queries without sending them.

**Parameters:**
- `key` - Key bytes or None (for null/zero-length key)
- `value` - Value bytes (MUST be at least 1 byte, cannot be None or empty)

**Returns:** List of DNS query strings

**Example:**
```python
queries = client.generate_queries_key_val(b'key', b'value')
print(f"Generated {len(queries)} queries")
for query in queries:
    print(query)
```

### Helper Functions

#### `calculate_safe_max_fragment_data_len(domain)`

Calculate safe maximum fragment data size based on domain length.

**Parameters:**
- `domain` - DNS domain string (e.g., `.example.com`)

**Returns:** Maximum safe fragment data length in bytes

**Raises:** `ValueError` if domain is too long (>143 chars)

**Formula:** `83 - len(domain) // 3`

**Example:**
```python
from mumbojumbo_client import calculate_safe_max_fragment_data_len

max_size = calculate_safe_max_fragment_data_len('.asd.qwe')
print(f"Max fragment size: {max_size} bytes")  # 81 bytes
```

#### Low-Level Functions

The following functions are available for custom implementations:

- `create_fragment(packet_id, frag_index, frag_count, frag_data, key_len=0)` - Build fragment with 18-byte header
- `encrypt_fragment(plaintext, server_client_key)` - Encrypt with NaCl SealedBox
- `base32_encode(data)` - Base32 encode (lowercase, no padding)
- `split_to_labels(data, max_len=63)` - Split into DNS labels
- `create_dns_query(encrypted, domain)` - Create full DNS query name
- `send_dns_query(dns_name)` - Send query via `dig` command
- `fragment_data(data, max_fragment_size)` - Split data into chunks (requires explicit size)

## Testing

```bash
# Run all tests
./venv/bin/pytest tests/test_client_python.py -v

# Run specific test class
./venv/bin/pytest tests/test_client_python.py::TestKeyValueEndToEnd -v
```

## Implementation Notes

- **Single file**: All code in one file for portability
- **Standard library**: Uses only Python stdlib except `pynacl`
- **No config files**: All configuration via command line or environment
- **Clean error handling**: Graceful failures with clear error messages
- **Cross-platform**: Works on Linux, macOS, Windows
- **Streaming**: Files and stdin are sent immediately (no buffering)

## Breaking Changes

### Recent Protocol Updates

**v2.0 (Key-Value Mode):**
- Header changed from 12 bytes to **18 bytes**
- Added `key_len` field (u8) at byte 17
- Changed `data_length` from u16 to u8 (max 255 bytes per fragment)
- Fragment size now **auto-calculated** based on domain (no more hardcoded 80 bytes)
- API changed from `send_data()` to `send_key_val(key, value)`
- Removed `MAX_FRAG_DATA_LEN` constant

**Migration:**
- Old clients using `send_data()` are incompatible
- Use `send_key_val(None, data)` for data-only transmission
- Fragment size is now automatic - don't specify unless needed

## Dependencies

```
pynacl>=1.5.0
```

## Requirements

- Python 3.7+
- `pynacl` library
- `dig` or `host` command (for DNS queries)

## License

See main project LICENSE file.
