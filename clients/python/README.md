# Mumbojumbo Python Client

Reference implementation of the mumbojumbo DNS protocol client in Python.

## Features

- **Minimalist design**: Only requires `pynacl` library
- **Simple CLI**: Three arguments (`-k`, `-d`, `-f`)
- **Stdin/file input**: Read from stdin or files
- **Multi-fragment support**: Automatically splits large messages
- **Verbose mode**: Debug output for troubleshooting

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
echo "Hello World" | ./mumbojumbo-client.py

# Option 2: Use command-line arguments
echo "Hello World" | ./mumbojumbo-client.py \
  -k mj_cli_f9ab4ab60d628f0a19e43592dfe078e16bbd37fa526ffef850411dad5e838c5e \
  -d .asd.qwe

# Send message from file
./mumbojumbo-client.py -f message.txt

# Verbose mode for debugging
echo "test" | ./mumbojumbo-client.py -v
```

### Command Line Options

- `-k, --key <public_key>` - Server public key in `mj_cli_<hex>` format (or use `MUMBOJUMBO_CLIENT_KEY` env var)
- `-d, --domain <domain>` - DNS domain suffix, e.g., `.asd.qwe` (or use `MUMBOJUMBO_DOMAIN` env var)
- `-f, --file <path>` - Input file path, use `-` for stdin (default: stdin)
- `-v, --verbose` - Enable verbose output to stderr

**Configuration Precedence:** CLI arguments > Environment variables

## Protocol Details

### Fragment Structure

Each message is split into 80-byte fragments with an 18-byte header:

```
Bytes 0-7:   packet_id (u64 big-endian) - 64-bit packet ID
Bytes 8-11:  frag_index (u32 big-endian) - supports up to 4.3 billion fragments
Bytes 12-15: frag_count (u32 big-endian) - supports up to 4.3 billion fragments
Bytes 16-17: data_length (u16 big-endian)
Bytes 18+:   fragment data (max 80 bytes)
```

### Protocol Capacity

- **Maximum fragments per packet:** 4,294,967,295 (2³² - 1)
- **Maximum packet size:** ~320 GB (343,597,383,600 bytes)
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
Input: "Hello World" (11 bytes)
→ Fragment: 18-byte header + 11 bytes = 29 bytes
→ Encrypt: 29 + 48 = 77 bytes (SealedBox overhead)
→ Base32: ~124 characters
→ DNS: <124-char-base32>.asd.qwe
```

## Programmatic API

```python
from mumbojumbo_client import MumbojumboClient

# Initialize client with mj_cli_ format key (auto-parsed)
client = MumbojumboClient(
    'mj_cli_f9ab4ab60d628f0a19e43592dfe078e16bbd37fa526ffef850411dad5e838c5e',
    '.asd.qwe'
)

# Send data (actually sends DNS queries)
results = client.send_data(b'Hello World')
for dns_query, success in results:
    print(f"{dns_query}: {'✓' if success else '✗'}")

# Or just generate queries without sending
queries = client.generate_queries(b'Test')
for query in queries:
    print(query)
```

### API Reference

#### `MumbojumboClient(server_client_key, domain, max_fragment_size=80)`

Creates a new client instance.

**Parameters:**
- `server_client_key` - Server's public key (mj_cli_ hex string, bytes, or nacl.public.PublicKey)
- `domain` - DNS domain suffix (e.g., `.asd.qwe`)
- `max_fragment_size` - Maximum bytes per fragment (default: 80)

#### `send_data(data)`

Send data via DNS queries.

**Parameters:**
- `data` - Data to send (bytes)

**Returns:** List of `(dns_query, success)` tuples

#### `generate_queries(data)`

Generate DNS queries without sending them.

**Parameters:**
- `data` - Data to encode (bytes)

**Returns:** List of DNS query strings

## Testing

```bash
# Run all tests
./venv/bin/pytest tests/test_client_python.py -v

# Run specific test class
./venv/bin/pytest tests/test_client_python.py::TestFragmentCreation -v
```

## Implementation Notes

- **Single file**: All code in one file for portability
- **Standard library**: Uses only Python stdlib except `pynacl`
- **No config files**: All configuration via command line
- **Clean error handling**: Graceful failures with clear error messages
- **Cross-platform**: Works on Linux, macOS, Windows

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
