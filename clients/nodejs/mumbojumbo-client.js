#!/usr/bin/env node
/**
 * Mumbojumbo DNS Client - Node.js Implementation
 *
 * Sends data through DNS queries using the mumbojumbo protocol.
 * Minimalist design: only requires tweetnacl for crypto.
 */

const nacl = require('tweetnacl');
const sealedBox = require('tweetnacl-sealedbox-js');
const { spawn } = require('child_process');
const fs = require('fs');

const MAX_FRAG_DATA_LEN = 80;
const DNS_LABEL_MAX_LEN = 63;

/**
 * Calculate safe maximum fragment data size using simplified formula.
 * Formula: 83 - len(domain) / 3
 *
 * This simplified formula is:
 * - Within 0-2 bytes of optimal for typical domains (3-12 chars)
 * - Within 5-7 bytes for longer domains (22-33 chars)
 * - Always safe (slightly conservative, never exceeds DNS limits)
 * - Requires only one arithmetic operation
 *
 * @param {string} domain - DNS domain string (e.g., '.example.com')
 * @returns {number} Maximum safe fragment data length in bytes
 * @throws {Error} If domain is too long (>143 chars)
 */
function calculateSafeMaxFragmentDataLen(domain) {
  const domainLen = domain.length;
  if (domainLen > 143) {
    throw new Error(`Domain too long: ${domainLen} chars (max 143)`);
  }
  return 83 - Math.floor(domainLen / 3);
}

/**
 * Base32 encode data (lowercase, no padding)
 */
function base32Encode(data) {
  const alphabet = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';
  let bits = 0;
  let value = 0;
  let output = '';

  for (let i = 0; i < data.length; i++) {
    value = (value << 8) | data[i];
    bits += 8;

    while (bits >= 5) {
      output += alphabet[(value >>> (bits - 5)) & 31];
      bits -= 5;
    }
  }

  if (bits > 0) {
    output += alphabet[(value << (5 - bits)) & 31];
  }

  return output.toLowerCase();
}

/**
 * Split string into DNS label chunks
 */
function splitToLabels(data, maxLen = DNS_LABEL_MAX_LEN) {
  const labels = [];
  for (let i = 0; i < data.length; i += maxLen) {
    labels.push(data.substring(i, i + maxLen));
  }
  return labels;
}

/**
 * Create fragment with 18-byte header
 *
 * Header format (big-endian):
 * - packet_id: u64 (0 to 2^64-1)
 * - frag_index: u32 (0-based fragment index)
 * - frag_count: u32 (total fragments in packet)
 * - frag_data_len: u16 (length of fragment data)
 */
function createFragment(packetId, fragIndex, fragCount, fragData) {
  if (packetId < 0 || packetId > Number.MAX_SAFE_INTEGER) {
    throw new Error(`packet_id out of range: ${packetId}`);
  }
  if (fragIndex < 0 || fragIndex >= fragCount) {
    throw new Error(`Invalid frag_index ${fragIndex} for frag_count ${fragCount}`);
  }
  if (fragCount < 0 || fragCount > 0xFFFFFFFF) {
    throw new Error(`frag_count out of u32 range: ${fragCount}`);
  }
  // Note: Fragment data length is validated by the client based on domain length
  // No hardcoded size check here to allow dynamic fragment sizes

  const header = Buffer.allocUnsafe(18);
  // Write u64 packet_id as two u32 values (big-endian)
  header.writeUInt32BE(Math.floor(packetId / 0x100000000), 0); // high 32 bits
  header.writeUInt32BE(packetId >>> 0, 4); // low 32 bits
  header.writeUInt32BE(fragIndex, 8);
  header.writeUInt32BE(fragCount, 12);
  header.writeUInt16BE(fragData.length, 16);

  return Buffer.concat([header, fragData]);
}

/**
 * Encrypt fragment using NaCl SealedBox
 */
function encryptFragment(plaintext, serverPubkey) {
  return Buffer.from(sealedBox.seal(plaintext, serverPubkey));
}

/**
 * Create DNS query name from encrypted fragment
 */
function createDnsQuery(encrypted, domain) {
  const b32 = base32Encode(encrypted);
  const labels = splitToLabels(b32, DNS_LABEL_MAX_LEN);
  return labels.join('.') + domain;
}

/**
 * Send DNS query using dig command
 */
async function sendDnsQuery(dnsName) {
  return new Promise((resolve) => {
    const dig = spawn('dig', ['+short', dnsName]);

    const timeout = setTimeout(() => {
      dig.kill();
      resolve(false);
    }, 5000);

    dig.on('close', (code) => {
      clearTimeout(timeout);
      resolve(code === 0);
    });

    dig.on('error', () => {
      clearTimeout(timeout);
      resolve(false);
    });
  });
}

/**
 * Split data into fragments
 */
function fragmentData(data, maxFragmentSize = MAX_FRAG_DATA_LEN) {
  if (!data || data.length === 0) {
    return [Buffer.alloc(0)];
  }

  const fragments = [];
  for (let i = 0; i < data.length; i += maxFragmentSize) {
    fragments.push(data.slice(i, i + maxFragmentSize));
  }
  return fragments;
}

/**
 * Mumbojumbo DNS Client
 */
class MumbojumboClient {
  /**
   * Initialize client
   *
   * @param {string|Uint8Array|Buffer} serverPublicKey - Server's public key (mj_cli_ hex string, Uint8Array, or Buffer)
   * @param {string} domain - DNS domain suffix (e.g., '.asd.qwe')
   * @param {number} maxFragmentSize - Maximum bytes per fragment (default: auto-calculated from domain)
   */
  constructor(serverPublicKey, domain, maxFragmentSize = null) {
    // Auto-parse hex key format if string is provided
    if (typeof serverPublicKey === 'string') {
      this.serverPubkey = this._parseKeyHex(serverPublicKey);
    } else if (Buffer.isBuffer(serverPublicKey)) {
      this.serverPubkey = new Uint8Array(serverPublicKey);
    } else {
      this.serverPubkey = serverPublicKey;
    }

    this.domain = domain.startsWith('.') ? domain : '.' + domain;

    // Auto-calculate max_fragment_size from domain if not provided
    if (maxFragmentSize === null || maxFragmentSize === undefined) {
      this.maxFragmentSize = calculateSafeMaxFragmentDataLen(this.domain);
    } else {
      this.maxFragmentSize = maxFragmentSize;
    }
    // Initialize with random u64 packet_id (using safe integer range)
    this._nextPacketId = Math.floor(Math.random() * Number.MAX_SAFE_INTEGER);
  }

  /**
   * Parse mj_cli_<hex> format key to Uint8Array (internal use)
   */
  _parseKeyHex(keyStr) {
    if (!keyStr.startsWith('mj_cli_')) {
      throw new Error('Key must start with "mj_cli_"');
    }
    const hexKey = keyStr.substring(7);
    if (hexKey.length !== 64) {
      throw new Error(`Invalid hex key length: expected 64, got ${hexKey.length}`);
    }
    if (!/^[0-9a-fA-F]{64}$/.test(hexKey)) {
      throw new Error('Invalid hex characters in key');
    }
    const bytes = new Uint8Array(32);
    for (let i = 0; i < 32; i++) {
      bytes[i] = parseInt(hexKey.substring(i * 2, i * 2 + 2), 16);
    }
    return bytes;
  }

  /**
   * Get next packet ID and increment counter (wraps at MAX_SAFE_INTEGER)
   */
  _getNextPacketId() {
    const packetId = this._nextPacketId;
    this._nextPacketId = (this._nextPacketId + 1) % Number.MAX_SAFE_INTEGER;
    return packetId;
  }

  /**
   * Internal method to generate DNS queries from data
   *
   * @param {Buffer} data - Bytes to send
   * @returns {Promise<Array>} List of DNS query strings
   */
  async _generateDnsQueries(data) {
    const packetId = this._getNextPacketId();

    // Fragment data
    const fragments = fragmentData(data, this.maxFragmentSize);
    const fragCount = fragments.length;

    const queries = [];
    for (let fragIndex = 0; fragIndex < fragments.length; fragIndex++) {
      const fragData = fragments[fragIndex];

      // Create fragment with header
      const plaintext = createFragment(packetId, fragIndex, fragCount, fragData);

      // Encrypt with SealedBox
      const encrypted = encryptFragment(plaintext, this.serverPubkey);

      // Create DNS query name
      const dnsName = createDnsQuery(encrypted, this.domain);
      queries.push(dnsName);
    }

    return queries;
  }

  /**
   * Send data via DNS queries
   *
   * @param {Buffer} data - Bytes to send
   * @returns {Promise<Array>} List of [dns_query, success] tuples
   */
  async sendData(data) {
    const queries = await this._generateDnsQueries(data);
    const results = [];
    for (const dnsName of queries) {
      const success = await sendDnsQuery(dnsName);
      results.push([dnsName, success]);
    }
    return results;
  }

  /**
   * Generate DNS queries without sending them
   *
   * @param {Buffer} data - Bytes to send
   * @returns {Promise<Array>} List of DNS query strings
   */
  async generateQueries(data) {
    return await this._generateDnsQueries(data);
  }
}

/**
 * CLI main function
 */
async function main() {
  const args = process.argv.slice(2);

  // Parse arguments
  let key = null;
  let domain = null;
  let file = '-';
  let verbose = false;

  for (let i = 0; i < args.length; i++) {
    if (args[i] === '-k' || args[i] === '--key') {
      key = args[++i];
    } else if (args[i] === '-d' || args[i] === '--domain') {
      domain = args[++i];
    } else if (args[i] === '-f' || args[i] === '--file') {
      file = args[++i];
    } else if (args[i] === '-v' || args[i] === '--verbose') {
      verbose = true;
    } else if (args[i] === '--help' || args[i] === '-h') {
      console.log(`
Mumbojumbo DNS Client - Node.js Implementation

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
      `);
      process.exit(0);
    }
  }

  if (!key || !domain) {
    console.error('Error: -k/--key and -d/--domain are required');
    console.error('Use --help for usage information');
    process.exit(1);
  }

  // Validate domain
  if (!domain.startsWith('.')) {
    console.error(`Warning: domain should start with '.', got '${domain}'`);
    console.error(`         Prepending '.' automatically`);
    domain = '.' + domain;
  }

  // Read input data
  let data;
  try {
    if (file === '-') {
      data = await readStdin();
    } else {
      data = fs.readFileSync(file);
    }
  } catch (err) {
    console.error(`Error reading input: ${err.message}`);
    process.exit(1);
  }

  if (verbose) {
    console.error(`Read ${data.length} bytes of input`);
  }

  // Create client - key parsing happens transparently in constructor
  let client;
  try {
    client = new MumbojumboClient(key, domain);
  } catch (err) {
    console.error(`Error initializing client: ${err.message}`);
    process.exit(1);
  }

  if (verbose) {
    const fragCount = fragmentData(data, MAX_FRAG_DATA_LEN).length;
    console.error(`Split into ${fragCount} fragment(s)`);
    console.error('');
  }

  // Send data
  let results;
  try {
    results = await client.sendData(data);
  } catch (err) {
    console.error(`Error sending data: ${err.message}`);
    if (verbose) {
      console.error(err.stack);
    }
    process.exit(1);
  }

  // Process results
  let successCount = 0;
  for (let fragIndex = 0; fragIndex < results.length; fragIndex++) {
    const [dnsName, success] = results[fragIndex];

    // Output query for inspection
    console.log(dnsName);

    if (success) {
      successCount++;
    }

    if (verbose) {
      const fragCount = results.length;
      console.error(`Fragment ${fragIndex + 1}/${fragCount}:`);

      // Calculate sizes for display
      const fragDataLen = Math.min(data.length - fragIndex * MAX_FRAG_DATA_LEN, MAX_FRAG_DATA_LEN);
      const plaintextLen = 18 + fragDataLen;
      const encryptedLen = plaintextLen + 48;

      console.error(`  Data length: ${fragDataLen} bytes`);
      console.error(`  Plaintext length: ${plaintextLen} bytes`);
      console.error(`  Encrypted length: ${encryptedLen} bytes`);
      console.error(`  DNS name length: ${dnsName.length} chars`);
      console.error(`  Sending query...`);

      if (success) {
        console.error(`  ✓ Sent successfully`);
      } else {
        console.error(`  ✗ Send failed (DNS query timed out or failed)`);
      }

      console.error('');
    }
  }

  if (verbose) {
    console.error(`Sent ${successCount}/${results.length} fragment(s) successfully`);
  }

  process.exit(successCount === results.length ? 0 : 1);
}

/**
 * Read all data from stdin
 */
function readStdin() {
  return new Promise((resolve, reject) => {
    const chunks = [];
    process.stdin.on('data', chunk => chunks.push(chunk));
    process.stdin.on('end', () => resolve(Buffer.concat(chunks)));
    process.stdin.on('error', reject);
  });
}

// Export for testing
module.exports = {
  base32Encode,
  splitToLabels,
  createFragment,
  encryptFragment,
  createDnsQuery,
  sendDnsQuery,
  fragmentData,
  MumbojumboClient,
  MAX_FRAG_DATA_LEN,
  DNS_LABEL_MAX_LEN
};

// Run CLI if executed directly
if (require.main === module) {
  main().catch(err => {
    console.error(`Fatal error: ${err.message}`);
    process.exit(1);
  });
}
