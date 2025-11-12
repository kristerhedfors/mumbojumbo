# Mumbojumbo Rust Client

Rust implementation of the mumbojumbo DNS protocol client.

## Features

- **Minimalist design**: Only requires `crypto_box`, `blake2`, `hex`, and `getrandom`
- **Simple CLI**: Three arguments (`-k`, `-d`, `-f`)
- **Stdin/file input**: Read from stdin or files
- **Multi-fragment support**: Automatically splits large messages
- **Verbose mode**: Debug output for troubleshooting
- **Safe Rust**: Memory-safe implementation with zero unsafe code

## Installation

```bash
cargo build --release
```

The compiled binary will be at `target/release/mumbojumbo-client`.

**Dependencies:**
- `crypto_box` - NaCl cryptography (X25519 + XSalsa20-Poly1305)
- `blake2` - BLAKE2b hashing for nonce derivation
- `hex` - Hex encoding/decoding for key parsing
- `getrandom` - Secure random number generation

## Usage

### Basic Examples

```bash
# Send message from stdin
echo "Hello World" | ./target/release/mumbojumbo-client \
  -k mj_cli_f9ab4ab60d628f0a19e43592dfe078e16bbd37fa526ffef850411dad5e838c5e \
  -d .asd.qwe

# Send message from file
./target/release/mumbojumbo-client \
  -k mj_cli_f9ab4ab60d628f0a19e43592dfe078e16bbd37fa526ffef850411dad5e838c5e \
  -d .asd.qwe \
  -f message.txt

# Verbose mode for debugging
echo "test" | ./target/release/mumbojumbo-client \
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

The client can be used as a library:

```rust
use mumbojumbo_client::{MumbojumboClient, MAX_FRAG_DATA_LEN};

fn main() -> Result<(), String> {
    // Initialize client with mj_cli_ format key (auto-parsed)
    let mut client = MumbojumboClient::new(
        "mj_cli_f9ab4ab60d628f0a19e43592dfe078e16bbd37fa526ffef850411dad5e838c5e",
        ".asd.qwe".to_string(),
        MAX_FRAG_DATA_LEN
    )?;

    // Send data (actually sends DNS queries)
    let results = client.send_data(b"Hello World")?;

    for result in results {
        println!("{}: {}", result.query, result.success);
    }

    // Or just generate queries without sending
    let queries = client.generate_queries(b"Test")?;

    for query in queries {
        println!("{}", query);
    }

    Ok(())
}
```

### API Reference

#### `MumbojumboClient::new(server_client_key_input: &str, domain: String, max_fragment_size: usize) -> Result<Self, String>`

Creates a new client instance.

**Parameters:**
- `server_client_key_input` - Server's public key (mj_cli_ hex string, or raw 64-char hex)
- `domain` - DNS domain suffix (e.g., `.asd.qwe`)
- `max_fragment_size` - Maximum bytes per fragment (default: 80)

**Returns:** MumbojumboClient instance or error

#### `client.send_data(&mut self, data: &[u8]) -> Result<Vec<QueryResult>, String>`

Send data via DNS queries.

**Parameters:**
- `data` - Data to send

**Returns:** Vector of QueryResult or error

#### `client.generate_queries(&mut self, data: &[u8]) -> Result<Vec<String>, String>`

Generate DNS queries without sending them.

**Parameters:**
- `data` - Data to encode

**Returns:** Vector of query strings or error

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
- Nonce derived via BLAKE2b-192(ephemeral_pubkey || recipient_pubkey)
- Overhead: 48 bytes per fragment (32-byte ephemeral key + 16-byte auth tag)
- **libsodium compatible**: Uses same format as libsodium's crypto_box_seal

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

## Testing

```bash
# Run all tests
cargo test

# Run with verbose output
cargo test -- --nocapture

# Run specific test
cargo test test_parse_valid_hex_key
```

**Test Coverage:** 21 unit tests covering:
- Unit tests: key parsing, base32, fragment creation, encryption
- Integration tests: client struct, data fragmentation
- All core functionality validated

## Implementation Notes

- **Single file**: All code in `src/main.rs` for simplicity
- **Minimal dependencies**: Only essential crates
- **No config files**: All configuration via command line
- **Clean error handling**: Result types with descriptive error messages
- **Memory safe**: No unsafe code, leveraging Rust's type system
- **Cross-platform**: Works on Linux, macOS, Windows

## Building for Different Platforms

```bash
# Linux
cargo build --release --target x86_64-unknown-linux-gnu

# macOS (Intel)
cargo build --release --target x86_64-apple-darwin

# macOS (Apple Silicon)
cargo build --release --target aarch64-apple-darwin

# Windows
cargo build --release --target x86_64-pc-windows-gnu
```

## Requirements

- Rust 1.70+
- `dig` command (for DNS queries)

## Encryption Format (libsodium crypto_box_seal compatible)

- **Format:** `ephemeral_pubkey(32) || box(plaintext)` with nonce = `BLAKE2b-192(ephemeral_pubkey || recipient_pubkey)`
- **Overhead:** 48 bytes (32-byte ephemeral pubkey + 16-byte auth tag)
- **Implementation:** Uses crypto_box crate with manual nonce derivation to match libsodium
- **Compatibility:** Works with Python, Node.js, Go, and C clients

## Performance

Rust client benefits from:
- Zero-cost abstractions
- Static compilation
- Efficient memory management
- Fast cryptographic operations

Typical performance: DNS query generation is ~10-50µs per fragment (DNS sending is the actual bottleneck).

## License

See main project LICENSE file.
