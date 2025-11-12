# Mumbojumbo C Client

C implementation of the mumbojumbo DNS protocol client.

## Features

- **Minimalist design**: Only requires `libsodium`
- **Simple CLI**: Three arguments (`-k`, `-d`, `-f`)
- **Stdin/file input**: Read from stdin or files
- **Multi-fragment support**: Automatically splits large messages
- **Verbose mode**: Debug output for troubleshooting
- **Portable C11**: Works on Linux, macOS, BSD, and other POSIX systems

## Installation

### Dependencies

**libsodium** is required for cryptographic operations:

```bash
# macOS (Homebrew)
brew install libsodium

# Ubuntu/Debian
sudo apt-get install libsodium-dev

# Fedora/RHEL
sudo dnf install libsodium-devel

# FreeBSD
pkg install libsodium

# From source
wget https://download.libsodium.org/libsodium/releases/libsodium-1.0.19.tar.gz
tar xzf libsodium-1.0.19.tar.gz
cd libsodium-1.0.19
./configure && make && sudo make install
```

### Building

```bash
make
```

The compiled binary will be `mumbojumbo-client`.

### Installing

```bash
sudo make install
```

This installs to `/usr/local/bin/mumbojumbo-client`.

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

- `-k <public_key>` - Server public key in `mj_cli_<hex>` format (required)
- `-d <domain>` - DNS domain suffix, e.g., `.asd.qwe` (required)
- `-f <path>` - Input file path, use `-` for stdin (default: stdin)
- `-v` - Enable verbose output to stderr
- `-h` - Show help message

## Programmatic API

The client can be used as a library by including the header and linking against the object file:

```c
#include "mumbojumbo-client.h"
#include <stdio.h>

int main(void) {
    if (sodium_init() < 0) {
        return 1;
    }

    // Initialize client with mj_cli_ format key (auto-parsed)
    MumbojumboClient *client = mumbojumbo_client_new(
        "mj_cli_f9ab4ab60d628f0a19e43592dfe078e16bbd37fa526ffef850411dad5e838c5e",
        ".asd.qwe",
        MAX_FRAG_DATA_LEN
    );

    // Send data (actually sends DNS queries)
    QueryResult *results;
    size_t count;

    const uint8_t data[] = "Hello World";
    if (mumbojumbo_send_data(client, data, sizeof(data) - 1, &results, &count) != 0) {
        mumbojumbo_client_free(client);
        return 1;
    }

    for (size_t i = 0; i < count; i++) {
        printf("%s: %s\n", results[i].query, results[i].success ? "success" : "failed");
    }

    // Or just generate queries without sending
    char **queries;
    if (mumbojumbo_generate_queries(client, data, sizeof(data) - 1, &queries, &count) != 0) {
        free_query_results(results, count);
        mumbojumbo_client_free(client);
        return 1;
    }

    for (size_t i = 0; i < count; i++) {
        printf("%s\n", queries[i]);
    }

    free_queries(queries, count);
    free_query_results(results, count);
    mumbojumbo_client_free(client);

    return 0;
}
```

**Compile:**
```bash
gcc -o myapp myapp.c mumbojumbo-client.c -lsodium
```

### API Reference

#### `MumbojumboClient *mumbojumbo_client_new(const char *server_client_key_input, const char *domain, size_t max_fragment_size)`

Creates a new client instance.

**Parameters:**
- `server_client_key_input` - Server's public key (mj_cli_ hex string, or raw 32-byte hex)
- `domain` - DNS domain suffix (e.g., `.asd.qwe`)
- `max_fragment_size` - Maximum bytes per fragment (default: 80)

**Returns:** Pointer to MumbojumboClient or NULL on error

#### `void mumbojumbo_client_free(MumbojumboClient *client)`

Frees client resources.

**Parameters:**
- `client` - Client to free

#### `int mumbojumbo_send_data(MumbojumboClient *client, const uint8_t *data, size_t data_len, QueryResult **out_results, size_t *out_count)`

Send data via DNS queries.

**Parameters:**
- `client` - Client instance
- `data` - Data to send
- `data_len` - Length of data
- `out_results` - Output array of QueryResult (caller must free with free_query_results)
- `out_count` - Output count of results

**Returns:** 0 on success, -1 on error

#### `void free_query_results(QueryResult *results, size_t count)`

Frees query results.

**Parameters:**
- `results` - Results to free
- `count` - Number of results

#### `int mumbojumbo_generate_queries(MumbojumboClient *client, const uint8_t *data, size_t data_len, char ***out_queries, size_t *out_count)`

Generate DNS queries without sending them.

**Parameters:**
- `client` - Client instance
- `data` - Data to encode
- `data_len` - Length of data
- `out_queries` - Output array of query strings (caller must free with free_queries)
- `out_count` - Output count of queries

**Returns:** 0 on success, -1 on error

#### `void free_queries(char **queries, size_t count)`

Frees query strings.

**Parameters:**
- `queries` - Queries to free
- `count` - Number of queries

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

- Uses **libsodium's crypto_box_seal** for anonymous public-key encryption
- No client keypair needed
- Overhead: 48 bytes per fragment (32-byte ephemeral key + 16-byte auth tag)
- **libsodium native**: Uses the standard crypto_box_seal implementation

### DNS Encoding

1. Fragment encrypted with crypto_box_seal
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

## Testing

```bash
# Run all tests
make test

# Run manually
make test-mumbojumbo-client
./test-mumbojumbo-client
```

**Test Coverage:** 23 tests covering:
- Unit tests: key parsing, base32, fragment creation, data fragmentation
- Integration tests: client API, query generation
- All core functionality validated

## Implementation Notes

- **Two files**: Header (`mumbojumbo-client.h`) + implementation (`mumbojumbo-client.c`)
- **Minimal dependencies**: Only libsodium for crypto
- **No config files**: All configuration via command line
- **Clean error handling**: Return codes with error messages to stderr
- **Memory safe**: Careful memory management with proper cleanup
- **POSIX compatible**: Works on all POSIX systems

## Building for Different Platforms

### Cross-compilation

```bash
# Linux to Windows (mingw)
make CC=x86_64-w64-mingw32-gcc LDFLAGS="-lsodium -lws2_32"

# Linux ARM
make CC=arm-linux-gnueabi-gcc

# Static binary (Linux)
make LDFLAGS="-lsodium -static"
```

### Platform-specific Notes

**macOS:** The Makefile automatically detects Homebrew libsodium installation.

**Linux:** Install libsodium-dev package for your distribution.

**Windows:** Use MSYS2 or mingw-w64 with libsodium installed.

**BSD:** Install libsodium from ports or packages.

## Requirements

- C11 compiler (gcc, clang)
- libsodium 1.0.18+
- `dig` command (for DNS queries)
- POSIX environment (Linux, macOS, BSD, etc.)

## Performance

C client benefits from:
- Direct system calls
- Minimal overhead
- Efficient memory management
- Fast cryptographic operations via libsodium

Typical performance: DNS query generation is ~5-20µs per fragment (DNS sending is the actual bottleneck).

## Security

- Uses libsodium's battle-tested crypto_box_seal
- Constant-time operations for cryptographic functions
- Secure random number generation via libsodium
- Memory cleared on cleanup
- No hardcoded secrets

## License

See main project LICENSE file.
