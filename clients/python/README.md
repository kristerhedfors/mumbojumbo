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

Each message is split into 80-byte fragments with a 12-byte header:

```
Bytes 0-1:   packet_id (u16 big-endian)
Bytes 2-5:   frag_index (u32 big-endian) - supports up to 4.3 billion fragments
Bytes 6-9:   frag_count (u32 big-endian) - supports up to 4.3 billion fragments
Bytes 10-11: data_length (u16 big-endian)
Bytes 12+:   fragment data (max 80 bytes)
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
→ Fragment: 12-byte header + 11 bytes = 23 bytes
→ Encrypt: 23 + 48 = 71 bytes (SealedBox overhead)
→ Base32: ~114 characters
→ DNS: <114-char-base32>.asd.qwe
```

## Testing

```bash
# Run all tests
pytest tests/test_client_python.py -v

# Run specific test class
pytest tests/test_client_python.py::TestFragmentCreation -v
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
