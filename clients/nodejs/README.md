# Mumbojumbo Node.js Client

Node.js implementation of the mumbojumbo DNS protocol client.

## Features

- **Minimalist design**: Only requires `tweetnacl` and `tweetnacl-sealedbox-js`
- **Simple CLI**: Three arguments (`-k`, `-d`, `-f`)
- **Stdin/file input**: Read from stdin or files
- **Multi-fragment support**: Automatically splits large messages
- **Verbose mode**: Debug output for troubleshooting
- **Modular API**: Clean programmatic interface

## Installation

```bash
npm install
```

**Dependencies:**
- `tweetnacl` - NaCl cryptography library
- `tweetnacl-sealedbox-js` - SealedBox encryption

## Usage

### Basic Examples

```bash
# Send message from stdin
echo "Hello World" | ./mumbojumbo-client.js \
  -k mj_pub_f9ab4ab60d628f0a19e43592dfe078e16bbd37fa526ffef850411dad5e838c5e \
  -d .asd.qwe

# Send message from file
./mumbojumbo-client.js \
  -k mj_pub_f9ab4ab60d628f0a19e43592dfe078e16bbd37fa526ffef850411dad5e838c5e \
  -d .asd.qwe \
  -f message.txt

# Verbose mode for debugging
echo "test" | ./mumbojumbo-client.js \
  -k mj_pub_... \
  -d .asd.qwe \
  -v
```

### Command Line Options

- `-k, --key <public_key>` - Server public key in `mj_pub_<hex>` format (required)
- `-d, --domain <domain>` - DNS domain suffix, e.g., `.asd.qwe` (required)
- `-f, --file <path>` - Input file path, use `-` for stdin (default: stdin)
- `-v, --verbose` - Enable verbose output to stderr

## Programmatic API

```javascript
const { MumbojumboClient, parseKeyHex } = require('./mumbojumbo-client.js');

// Initialize client
const serverKey = parseKeyHex('mj_pub_f9ab4ab60d628f0a19e43592dfe078e16bbd37fa526ffef850411dad5e838c5e');
const client = new MumbojumboClient(serverKey, '.asd.qwe');

// Send data (actually sends DNS queries)
const results = await client.sendData(Buffer.from('Hello World'));
for (const [dnsQuery, success] of results) {
  console.log(`${dnsQuery}: ${success ? '✓' : '✗'}`);
}

// Or just generate queries without sending
const queries = await client.generateQueries(Buffer.from('Test'));
for (const query of queries) {
  console.log(query);
}
```

### API Reference

#### `MumbojumboClient(serverPublicKey, domain, maxFragmentSize = 80)`

Creates a new client instance.

**Parameters:**
- `serverPublicKey` - Server's public key (Uint8Array or Buffer, 32 bytes)
- `domain` - DNS domain suffix (e.g., `.asd.qwe`)
- `maxFragmentSize` - Maximum bytes per fragment (default: 80)

#### `async sendData(data, sendQueries = true)`

Send data via DNS queries.

**Parameters:**
- `data` - Data to send (Buffer)
- `sendQueries` - If true, actually sends DNS queries (default: true)

**Returns:** `[[dnsQuery, success], ...]`

#### `async generateQueries(data)`

Generate DNS queries without sending them.

**Parameters:**
- `data` - Data to encode (Buffer)

**Returns:** `[query1, query2, ...]`

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
node --test test-mumbojumbo-client.js

# Run with verbose output
node --test --test-reporter=spec test-mumbojumbo-client.js
```

**Test Coverage:** 50 tests covering:
- Unit tests: key parsing, base32, fragment creation, encryption
- Integration tests: client class, packet ID management
- E2E tests: full encrypt/decrypt flow, multi-fragment
- CLI tests: help, arguments, file/stdin input

## Implementation Notes

- **Single file**: All code in one file for portability
- **Minimal dependencies**: Only tweetnacl libraries
- **No config files**: All configuration via command line
- **Clean error handling**: Graceful failures with clear error messages
- **Cross-platform**: Works on Linux, macOS, Windows

## Requirements

- Node.js 18.0.0+
- `tweetnacl` library
- `tweetnacl-sealedbox-js` library
- `dig` command (for DNS queries)

## License

See main project LICENSE file.
