use blake2::{Blake2b, Digest};
use crypto_box::{
    aead::Aead,
    PublicKey, SalsaBox, SecretKey,
};
use getrandom::getrandom;
use rand_core::OsRng;
use std::env;
use std::io::{self, Read};
use std::process::{Command, exit};

const MAX_FRAG_DATA_LEN: usize = 80;
const DNS_LABEL_MAX_LEN: usize = 63;
const HEADER_SIZE: usize = 18; // 18-byte header: u64 + u32 + u32 + u16
const SEALED_BOX_OH: usize = 48; // 32-byte ephemeral pubkey + 16-byte tag

/// Key input type to support both string and byte array
pub enum KeyInput {
    String(String),
    Bytes([u8; 32]),
}

impl KeyInput {
    fn parse(self) -> Result<[u8; 32], String> {
        match self {
            KeyInput::String(s) => parse_key_hex(&s),
            KeyInput::Bytes(b) => Ok(b),
        }
    }
}

impl From<String> for KeyInput {
    fn from(s: String) -> Self {
        KeyInput::String(s)
    }
}

impl From<&str> for KeyInput {
    fn from(s: &str) -> Self {
        KeyInput::String(s.to_string())
    }
}

impl From<[u8; 32]> for KeyInput {
    fn from(b: [u8; 32]) -> Self {
        KeyInput::Bytes(b)
    }
}

/// Calculate safe maximum fragment data size using simplified formula.
/// Formula: 83 - len(domain) / 3
///
/// This simplified formula is:
/// - Within 0-2 bytes of optimal for typical domains (3-12 chars)
/// - Within 5-7 bytes for longer domains (22-33 chars)
/// - Always safe (slightly conservative, never exceeds DNS limits)
/// - Requires only one arithmetic operation
///
/// Returns maximum safe fragment data length in bytes, or error if domain is too long (>143 chars).
fn calculate_safe_max_fragment_data_len(domain: &str) -> Result<usize, String> {
    let domain_len = domain.len();
    if domain_len > 143 {
        return Err(format!("Domain too long: {} chars (max 143)", domain_len));
    }
    Ok(83 - domain_len / 3)
}

/// MumbojumboClient handles DNS tunneling operations
pub struct MumbojumboClient {
    server_client_key: [u8; 32],
    domain: String,
    max_fragment_size: usize,
    next_packet_id: u64,
}

impl MumbojumboClient {
    /// Creates a new client instance
    /// Accepts either a string key (mj_cli_<hex>) or raw [u8; 32]
    pub fn new<K: Into<KeyInput>>(server_client_key: K, domain: String, max_fragment_size: usize) -> Result<Self, String> {
        let server_client_key = server_client_key.into().parse()?;

        let domain = if domain.starts_with('.') {
            domain
        } else {
            format!(".{}", domain)
        };

        // Auto-calculate max_fragment_size from domain if 0 (or use provided value)
        let max_fragment_size = if max_fragment_size == 0 {
            calculate_safe_max_fragment_data_len(&domain)?
        } else {
            max_fragment_size
        };

        // Initialize with cryptographically random packet ID (u64)
        let mut random_bytes = [0u8; 8];
        getrandom(&mut random_bytes).expect("Failed to generate random bytes");
        let next_packet_id = u64::from_be_bytes(random_bytes);

        Ok(Self {
            server_client_key,
            domain,
            max_fragment_size,
            next_packet_id,
        })
    }

    /// Returns the next packet ID and increments counter (wraps at 2^64-1)
    fn get_next_packet_id(&mut self) -> u64 {
        let packet_id = self.next_packet_id;
        self.next_packet_id = self.next_packet_id.wrapping_add(1);
        packet_id
    }

    /// Send data via DNS queries
    pub fn send_data(&mut self, data: &[u8], send_queries: bool) -> Result<Vec<QueryResult>, String> {
        let packet_id = self.get_next_packet_id();
        let fragments = fragment_data(data, self.max_fragment_size);
        let frag_count = fragments.len() as u32;

        let mut results = Vec::new();

        for (frag_index, frag_data) in fragments.iter().enumerate() {
            // Create fragment with header
            let plaintext = create_fragment(packet_id, frag_index as u32, frag_count, frag_data)?;

            // Encrypt with SealedBox
            let encrypted = encrypt_sealed_box(&plaintext, &self.server_client_key)?;

            // Create DNS query name
            let dns_name = create_dns_query(&encrypted, &self.domain);

            // Optionally send query
            let success = if send_queries {
                send_dns_query(&dns_name)
            } else {
                true
            };

            results.push(QueryResult {
                query: dns_name,
                success,
            });
        }

        Ok(results)
    }

    /// Generate DNS queries without sending them
    pub fn generate_queries(&mut self, data: &[u8]) -> Result<Vec<String>, String> {
        let results = self.send_data(data, false)?;
        Ok(results.into_iter().map(|r| r.query).collect())
    }
}

/// Result of sending a DNS query
#[derive(Debug)]
pub struct QueryResult {
    pub query: String,
    pub success: bool,
}

/// Parses a key in mj_cli_<hex> format (internal use)
fn parse_key_hex(key_str: &str) -> Result<[u8; 32], String> {
    if !key_str.starts_with("mj_cli_") {
        return Err("key must start with \"mj_cli_\"".to_string());
    }

    let hex_key = &key_str[7..];
    if hex_key.len() != 64 {
        return Err(format!(
            "invalid hex key length: expected 64, got {}",
            hex_key.len()
        ));
    }

    let decoded = hex::decode(hex_key)
        .map_err(|e| format!("invalid hex characters in key: {}", e))?;

    let mut key = [0u8; 32];
    key.copy_from_slice(&decoded);
    Ok(key)
}

/// Base32 encode (lowercase, no padding)
pub fn base32_encode(data: &[u8]) -> String {
    const ALPHABET: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
    let mut bits = 0u32;
    let mut value = 0u32;
    let mut output = String::new();

    for &b in data {
        value = (value << 8) | (b as u32);
        bits += 8;

        while bits >= 5 {
            output.push(ALPHABET[((value >> (bits - 5)) & 31) as usize] as char);
            bits -= 5;
        }
    }

    if bits > 0 {
        output.push(ALPHABET[((value << (5 - bits)) & 31) as usize] as char);
    }

    output.to_lowercase()
}

/// Split string into DNS labels of max length
pub fn split_to_labels(data: &str, max_len: usize) -> Vec<String> {
    if data.is_empty() {
        return Vec::new();
    }

    data.as_bytes()
        .chunks(max_len)
        .map(|chunk| String::from_utf8_lossy(chunk).to_string())
        .collect()
}

/// Create fragment with 18-byte header
pub fn create_fragment(
    packet_id: u64,
    frag_index: u32,
    frag_count: u32,
    frag_data: &[u8],
) -> Result<Vec<u8>, String> {
    if frag_index >= frag_count {
        return Err(format!(
            "invalid frag_index {} for frag_count {}",
            frag_index, frag_count
        ));
    }

    if frag_data.len() > MAX_FRAG_DATA_LEN {
        return Err(format!(
            "fragment data too large: {} > {}",
            frag_data.len(),
            MAX_FRAG_DATA_LEN
        ));
    }

    let mut header = vec![0u8; HEADER_SIZE];
    header[0..8].copy_from_slice(&packet_id.to_be_bytes());
    header[8..12].copy_from_slice(&frag_index.to_be_bytes());
    header[12..16].copy_from_slice(&frag_count.to_be_bytes());
    header[16..18].copy_from_slice(&(frag_data.len() as u16).to_be_bytes());

    let mut fragment = header;
    fragment.extend_from_slice(frag_data);
    Ok(fragment)
}

/// Encrypt plaintext using libsodium-compatible SealedBox
/// Format: ephemeral_pubkey(32) || box(plaintext) with nonce derived from BLAKE2b
pub fn encrypt_sealed_box(plaintext: &[u8], recipient_pubkey: &[u8; 32]) -> Result<Vec<u8>, String> {
    // Generate ephemeral keypair
    let ephemeral_secret = SecretKey::generate(&mut OsRng);
    let ephemeral_public = ephemeral_secret.public_key();

    // Derive nonce from BLAKE2b(ephemeral_pubkey || recipient_pubkey)
    let nonce = derive_nonce(ephemeral_public.as_bytes(), recipient_pubkey)?;

    // Create box and encrypt
    let recipient_pk = PublicKey::from(*recipient_pubkey);
    let salsa_box = SalsaBox::new(&recipient_pk, &ephemeral_secret);

    let encrypted = salsa_box
        .encrypt(&nonce, plaintext)
        .map_err(|e| format!("encryption failed: {}", e))?;

    // Prepend ephemeral public key (libsodium SealedBox format)
    let mut result = Vec::with_capacity(32 + encrypted.len());
    result.extend_from_slice(ephemeral_public.as_bytes());
    result.extend_from_slice(&encrypted);

    Ok(result)
}

/// Derive nonce from two public keys using BLAKE2b-192
fn derive_nonce(ephemeral_pub: &[u8], recipient_pub: &[u8]) -> Result<crypto_box::Nonce, String> {
    let mut hasher = Blake2b::<blake2::digest::consts::U24>::new();
    hasher.update(ephemeral_pub);
    hasher.update(recipient_pub);
    let digest = hasher.finalize();

    let mut nonce_bytes = [0u8; 24];
    nonce_bytes.copy_from_slice(&digest);
    Ok(crypto_box::Nonce::from(nonce_bytes))
}

/// Create DNS query name from encrypted data
pub fn create_dns_query(encrypted: &[u8], domain: &str) -> String {
    let b32 = base32_encode(encrypted);
    let labels = split_to_labels(&b32, DNS_LABEL_MAX_LEN);
    format!("{}{}", labels.join("."), domain)
}

/// Send DNS query using dig command
pub fn send_dns_query(dns_name: &str) -> bool {
    Command::new("dig")
        .arg("+short")
        .arg(dns_name)
        .output()
        .is_ok()
}

/// Fragment data into chunks
pub fn fragment_data(data: &[u8], max_fragment_size: usize) -> Vec<Vec<u8>> {
    if data.is_empty() {
        return vec![Vec::new()];
    }

    data.chunks(max_fragment_size)
        .map(|chunk| chunk.to_vec())
        .collect()
}

fn print_usage() {
    eprintln!(
        r#"
Mumbojumbo DNS Client - Rust Implementation

Usage: mumbojumbo-client -k <key> -d <domain> [options]

Required arguments:
  -k, --key <public_key>     Server public key (mj_cli_... format)
  -d, --domain <domain>      DNS domain suffix (e.g., .asd.qwe)

Optional arguments:
  -f, --file <path>          Input file path (use "-" for stdin, default: stdin)
  -v, --verbose              Enable verbose output to stderr

Examples:
  echo "Hello" | mumbojumbo-client -k mj_cli_abc123... -d .asd.qwe
  mumbojumbo-client -k mj_cli_abc123... -d .asd.qwe -f message.txt
  mumbojumbo-client -k mj_cli_abc123... -d .asd.qwe -v
"#
    );
}

fn main() {
    let args: Vec<String> = env::args().collect();

    let mut key_str = String::new();
    let mut domain = String::new();
    let mut file_path = String::from("-");
    let mut verbose = false;

    let mut i = 1;
    while i < args.len() {
        match args[i].as_str() {
            "-k" | "--key" => {
                if i + 1 >= args.len() {
                    eprintln!("Error: {} requires an argument", args[i]);
                    exit(1);
                }
                key_str = args[i + 1].clone();
                i += 2;
            }
            "-d" | "--domain" => {
                if i + 1 >= args.len() {
                    eprintln!("Error: {} requires an argument", args[i]);
                    exit(1);
                }
                domain = args[i + 1].clone();
                i += 2;
            }
            "-f" | "--file" => {
                if i + 1 >= args.len() {
                    eprintln!("Error: {} requires an argument", args[i]);
                    exit(1);
                }
                file_path = args[i + 1].clone();
                i += 2;
            }
            "-v" | "--verbose" => {
                verbose = true;
                i += 1;
            }
            "-h" | "--help" => {
                print_usage();
                exit(0);
            }
            _ => {
                eprintln!("Error: unknown option '{}'", args[i]);
                eprintln!("Use --help for usage information");
                exit(1);
            }
        }
    }

    if key_str.is_empty() || domain.is_empty() {
        eprintln!("Error: -k/--key and -d/--domain are required");
        eprintln!("Use --help for usage information");
        exit(1);
    }

    // Validate domain
    if !domain.starts_with('.') {
        eprintln!("Warning: domain should start with '.', got '{}'", domain);
        eprintln!("         Prepending '.' automatically");
    }

    // Read input data
    let data = if file_path == "-" {
        let mut buffer = Vec::new();
        io::stdin()
            .read_to_end(&mut buffer)
            .expect("Failed to read from stdin");
        buffer
    } else {
        std::fs::read(&file_path).expect("Failed to read input file")
    };

    if verbose {
        eprintln!("Read {} bytes of input", data.len());
    }

    // Create client - key parsing happens transparently in constructor
    // Pass 0 to auto-calculate max fragment size from domain
    let mut client = match MumbojumboClient::new(key_str, domain, 0) {
        Ok(c) => c,
        Err(e) => {
            eprintln!("Error initializing client: {}", e);
            exit(1);
        }
    };

    if verbose {
        let fragments = fragment_data(&data, MAX_FRAG_DATA_LEN);
        eprintln!("Split into {} fragment(s)\n", fragments.len());
    }

    // Send data
    let results = match client.send_data(&data, true) {
        Ok(r) => r,
        Err(e) => {
            eprintln!("Error sending data: {}", e);
            exit(1);
        }
    };

    // Process results
    let mut success_count = 0;
    for (frag_index, result) in results.iter().enumerate() {
        // Output query for inspection
        println!("{}", result.query);

        if result.success {
            success_count += 1;
        }

        if verbose {
            let frag_count = results.len();
            eprintln!("Fragment {}/{}:", frag_index + 1, frag_count);

            // Calculate sizes for display
            let frag_data_len = if frag_index == results.len() - 1 && data.len() % MAX_FRAG_DATA_LEN != 0 {
                data.len() % MAX_FRAG_DATA_LEN
            } else {
                MAX_FRAG_DATA_LEN
            };
            let plaintext_len = HEADER_SIZE + frag_data_len;
            let encrypted_len = plaintext_len + SEALED_BOX_OH;

            eprintln!("  Data length: {} bytes", frag_data_len);
            eprintln!("  Plaintext length: {} bytes", plaintext_len);
            eprintln!("  Encrypted length: {} bytes", encrypted_len);
            eprintln!("  DNS name length: {} chars", result.query.len());
            eprintln!("  Sending query...");

            if result.success {
                eprintln!("  ✓ Sent successfully");
            } else {
                eprintln!("  ✗ Send failed (DNS query timed out or failed)");
            }

            eprintln!();
        }
    }

    if verbose {
        eprintln!("Sent {}/{} fragment(s) successfully", success_count, results.len());
    }

    if success_count != results.len() {
        exit(1);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_valid_hex_key() {
        let valid_key = format!("mj_cli_{}", "a".repeat(64));
        let result = parse_key_hex(&valid_key).unwrap();
        assert_eq!(result[0], 0xaa);
    }

    #[test]
    fn test_reject_key_without_prefix() {
        let result = parse_key_hex(&"a".repeat(64));
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("must start with"));
    }

    #[test]
    fn test_reject_key_with_wrong_length() {
        let result = parse_key_hex(&format!("mj_cli_{}", "a".repeat(32)));
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("invalid hex key length"));
    }

    #[test]
    fn test_base32_encode_basic() {
        let data = b"hello";
        let encoded = base32_encode(data);
        assert_eq!(encoded, "nbswy3dp");
    }

    #[test]
    fn test_base32_encode_empty() {
        let encoded = base32_encode(&[]);
        assert_eq!(encoded, "");
    }

    #[test]
    fn test_base32_encode_lowercase() {
        let data = b"TEST";
        let encoded = base32_encode(data);
        assert_eq!(encoded, encoded.to_lowercase());
    }

    #[test]
    fn test_base32_encode_no_padding() {
        let data = b"hello world";
        let encoded = base32_encode(data);
        assert!(!encoded.contains('='));
    }

    #[test]
    fn test_split_to_labels_short() {
        let labels = split_to_labels("abc", DNS_LABEL_MAX_LEN);
        assert_eq!(labels, vec!["abc"]);
    }

    #[test]
    fn test_split_to_labels_exact_63() {
        let data = "a".repeat(63);
        let labels = split_to_labels(&data, DNS_LABEL_MAX_LEN);
        assert_eq!(labels.len(), 1);
        assert_eq!(labels[0], data);
    }

    #[test]
    fn test_split_to_labels_long() {
        let data = "a".repeat(100);
        let labels = split_to_labels(&data, DNS_LABEL_MAX_LEN);
        assert_eq!(labels.len(), 2);
        assert_eq!(labels[0].len(), 63);
        assert_eq!(labels[1].len(), 37);
    }

    #[test]
    fn test_split_to_labels_empty() {
        let labels = split_to_labels("", DNS_LABEL_MAX_LEN);
        assert_eq!(labels.len(), 0);
    }

    #[test]
    fn test_create_basic_fragment() {
        let frag_data = b"test";
        let frag = create_fragment(100, 0, 1, frag_data).unwrap();

        assert_eq!(frag.len(), HEADER_SIZE + 4);

        let packet_id = u64::from_be_bytes([frag[0], frag[1], frag[2], frag[3], frag[4], frag[5], frag[6], frag[7]]);
        let frag_index = u32::from_be_bytes([frag[8], frag[9], frag[10], frag[11]]);
        let frag_count = u32::from_be_bytes([frag[12], frag[13], frag[14], frag[15]]);
        let data_len = u16::from_be_bytes([frag[16], frag[17]]);

        assert_eq!(packet_id, 100);
        assert_eq!(frag_index, 0);
        assert_eq!(frag_count, 1);
        assert_eq!(data_len, 4);
        assert_eq!(&frag[HEADER_SIZE..], frag_data);
    }

    #[test]
    fn test_create_empty_fragment() {
        let frag = create_fragment(1, 0, 1, &[]).unwrap();
        assert_eq!(frag.len(), HEADER_SIZE);

        let data_len = u16::from_be_bytes([frag[16], frag[17]]);
        assert_eq!(data_len, 0);
    }

    #[test]
    fn test_reject_oversized_fragment() {
        let oversized = vec![0u8; MAX_FRAG_DATA_LEN + 1];
        let result = create_fragment(1, 0, 1, &oversized);
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("too large"));
    }

    #[test]
    fn test_reject_invalid_frag_index() {
        let result = create_fragment(1, 5, 5, b"test");
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("invalid frag_index"));
    }

    #[test]
    fn test_fragment_small_data() {
        let data = b"small";
        let fragments = fragment_data(data, MAX_FRAG_DATA_LEN);
        assert_eq!(fragments.len(), 1);
        assert_eq!(fragments[0], data);
    }

    #[test]
    fn test_fragment_exact_max_size() {
        let data = vec![0u8; MAX_FRAG_DATA_LEN];
        let fragments = fragment_data(&data, MAX_FRAG_DATA_LEN);
        assert_eq!(fragments.len(), 1);
        assert_eq!(fragments[0].len(), MAX_FRAG_DATA_LEN);
    }

    #[test]
    fn test_fragment_overflow() {
        let data = vec![0u8; MAX_FRAG_DATA_LEN + 10];
        let fragments = fragment_data(&data, MAX_FRAG_DATA_LEN);
        assert_eq!(fragments.len(), 2);
        assert_eq!(fragments[0].len(), MAX_FRAG_DATA_LEN);
        assert_eq!(fragments[1].len(), 10);
    }

    #[test]
    fn test_fragment_empty_data() {
        let fragments = fragment_data(&[], MAX_FRAG_DATA_LEN);
        assert_eq!(fragments.len(), 1);
        assert_eq!(fragments[0].len(), 0);
    }

    #[test]
    fn test_encrypt_fragment() {
        let server_client_key = [0xaau8; 32];
        let plaintext = b"secret data";
        let encrypted = encrypt_sealed_box(plaintext, &server_client_key).unwrap();
        assert_eq!(encrypted.len(), plaintext.len() + SEALED_BOX_OH);
    }

    #[test]
    fn test_create_basic_dns_query() {
        let encrypted = vec![b'a'; 10];
        let query = create_dns_query(&encrypted, ".asd.qwe");
        assert!(query.ends_with(".asd.qwe"));
    }

    #[test]
    fn test_create_query_from_empty_data() {
        let query = create_dns_query(&[], ".asd.qwe");
        assert_eq!(query, ".asd.qwe");
    }
}
