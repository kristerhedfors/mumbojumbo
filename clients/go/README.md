# Mumbojumbo Go Client

Go implementation of the mumbojumbo DNS protocol client.

## Features

- **Minimalist design**: Only requires `golang.org/x/crypto`
- **Simple CLI**: Three arguments (`-k`, `-d`, `-f`)
- **Stdin/file input**: Read from stdin or files
- **Multi-fragment support**: Automatically splits large messages
- **Verbose mode**: Debug output for troubleshooting
- **Modular API**: Clean struct-based interface

## Installation

```bash
go mod download
go build -o mumbojumbo-client mumbojumbo-client.go
```

**Dependencies:**
- `golang.org/x/crypto` - NaCl cryptography implementation

## Usage

### Basic Examples

```bash
# Send message from stdin
echo "Hello World" | ./mumbojumbo-client \
  -k mj_cli_f9ab4ab60d628f0a19e43592dfe078e16bbd37fa526ffef850411dad5e838c5e \
  -d .asd.qwe

# Send message from file
./mumbojumbo-client \
  -k mj_cli_f9ab4ab60d628f0a19e43592dfe078e16bbd37fa526ffef850411dad5e838c5e \
  -d .asd.qwe \
  -f message.txt

# Verbose mode for debugging
echo "test" | ./mumbojumbo-client \
  -k mj_cli_... \
  -d .asd.qwe \
  -v
```

### Command Line Options

- `-k, --key <public_key>` - Server public key in `mj_cli_<hex>` format (required)
- `-d, --domain <domain>` - DNS domain suffix, e.g., `.asd.qwe` (required)
- `-f, --file <path>` - Input file path, use `-` for stdin (default: stdin)
- `-v, --verbose` - Enable verbose output to stderr

## Programmatic API

```go
package main

import (
    "fmt"
    "log"
)

func main() {
    // Parse server public key
    serverKey, err := ParseKeyHex("mj_cli_f9ab4ab60d628f0a19e43592dfe078e16bbd37fa526ffef850411dad5e838c5e")
    if err != nil {
        log.Fatal(err)
    }

    // Initialize client
    client := NewMumbojumboClient(serverKey, ".asd.qwe", 80)

    // Send data (actually sends DNS queries)
    results, err := client.SendData([]byte("Hello World"), true)
    if err != nil {
        log.Fatal(err)
    }

    for _, result := range results {
        fmt.Printf("%s: %v\n", result.Query, result.Success)
    }

    // Or just generate queries without sending
    queries, err := client.GenerateQueries([]byte("Test"))
    if err != nil {
        log.Fatal(err)
    }

    for _, query := range queries {
        fmt.Println(query)
    }
}
```

### API Reference

#### `ParseKeyHex(keyStr string) ([32]byte, error)`

Parses a server public key in `mj_cli_<hex>` format.

**Parameters:**
- `keyStr` - Key string in mj_cli_ format

**Returns:** 32-byte array or error

#### `NewMumbojumboClient(serverPubkey [32]byte, domain string, maxFragmentSize int) *MumbojumboClient`

Creates a new client instance.

**Parameters:**
- `serverPubkey` - Server's public key (32 bytes)
- `domain` - DNS domain suffix (e.g., `.asd.qwe`)
- `maxFragmentSize` - Maximum bytes per fragment (default: 80)

**Returns:** Pointer to MumbojumboClient

#### `(c *MumbojumboClient) SendData(data []byte, sendQueries bool) ([]QueryResult, error)`

Send data via DNS queries.

**Parameters:**
- `data` - Data to send
- `sendQueries` - If true, actually sends DNS queries (default: true)

**Returns:** Slice of QueryResult or error

#### `(c *MumbojumboClient) GenerateQueries(data []byte) ([]string, error)`

Generate DNS queries without sending them.

**Parameters:**
- `data` - Data to encode

**Returns:** Slice of query strings or error

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
- Nonce derived via BLAKE2b(ephemeral_pubkey || recipient_pubkey)
- Overhead: 48 bytes per fragment (32-byte ephemeral key + 16-byte auth tag)

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
go test

# Run with verbose output
go test -v

# Run specific test
go test -run TestEncryptDecrypt
```

**Test Coverage:** 43 tests covering:
- Unit tests: key parsing, base32, fragment creation, encryption
- Integration tests: client struct, packet ID management
- E2E tests: full encrypt/decrypt flow, multi-fragment
- All core functionality validated

## Implementation Notes

- **Single file**: All code in one file for portability
- **Minimal dependencies**: Only golang.org/x/crypto
- **No config files**: All configuration via command line
- **Clean error handling**: Graceful failures with clear error messages
- **Cross-platform**: Works on Linux, macOS, Windows

## Requirements

- Go 1.21+
- `golang.org/x/crypto` library
- `dig` command (for DNS queries)

## Building

```bash
# Build binary
go build -o mumbojumbo-client mumbojumbo-client.go

# Build for specific platform
GOOS=linux GOARCH=amd64 go build -o mumbojumbo-client-linux mumbojumbo-client.go
GOOS=darwin GOARCH=arm64 go build -o mumbojumbo-client-mac mumbojumbo-client.go
GOOS=windows GOARCH=amd64 go build -o mumbojumbo-client.exe mumbojumbo-client.go
```

## License

See main project LICENSE file.
