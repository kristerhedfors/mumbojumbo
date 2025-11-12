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
 * Parse mj_pub_<hex> format key to Uint8Array
 */
function parseKeyHex(keyStr) {
  if (!keyStr.startsWith('mj_pub_')) {
    throw new Error('Key must start with "mj_pub_"');
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
 * Create fragment with 12-byte header
 *
 * Header format (big-endian):
 * - packet_id: u16 (0-65535)
 * - frag_index: u32 (0-based fragment index)
 * - frag_count: u32 (total fragments in packet)
 * - frag_data_len: u16 (length of fragment data)
 */
function createFragment(packetId, fragIndex, fragCount, fragData) {
  if (packetId < 0 || packetId > 0xFFFF) {
    throw new Error(`packet_id out of range: ${packetId}`);
  }
  if (fragIndex < 0 || fragIndex >= fragCount) {
    throw new Error(`Invalid frag_index ${fragIndex} for frag_count ${fragCount}`);
  }
  if (fragCount < 0 || fragCount > 0xFFFFFFFF) {
    throw new Error(`frag_count out of u32 range: ${fragCount}`);
  }
  if (fragData.length > MAX_FRAG_DATA_LEN) {
    throw new Error(`Fragment data too large: ${fragData.length} > ${MAX_FRAG_DATA_LEN}`);
  }

  const header = Buffer.allocUnsafe(12);
  header.writeUInt16BE(packetId, 0);
  header.writeUInt32BE(fragIndex, 2);
  header.writeUInt32BE(fragCount, 6);
  header.writeUInt16BE(fragData.length, 10);

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
   * @param {Uint8Array|Buffer} serverPublicKey - Server's public key (32 bytes)
   * @param {string} domain - DNS domain suffix (e.g., '.asd.qwe')
   * @param {number} maxFragmentSize - Maximum bytes per fragment (default: 80)
   */
  constructor(serverPublicKey, domain, maxFragmentSize = MAX_FRAG_DATA_LEN) {
    if (Buffer.isBuffer(serverPublicKey)) {
      this.serverPubkey = new Uint8Array(serverPublicKey);
    } else {
      this.serverPubkey = serverPublicKey;
    }

    this.domain = domain.startsWith('.') ? domain : '.' + domain;
    this.maxFragmentSize = maxFragmentSize;
    this._nextPacketId = Math.floor(Math.random() * 0x10000);
  }

  /**
   * Get next packet ID and increment counter (wraps at 0xFFFF)
   */
  _getNextPacketId() {
    const packetId = this._nextPacketId;
    this._nextPacketId = (this._nextPacketId + 1) & 0xFFFF;
    return packetId;
  }

  /**
   * Send data via DNS queries
   *
   * @param {Buffer} data - Bytes to send
   * @param {boolean} sendQueries - If true, actually send DNS queries
   * @returns {Promise<Array>} List of [dns_query, success] tuples
   */
  async sendData(data, sendQueries = true) {
    const packetId = this._getNextPacketId();

    // Fragment data
    const fragments = fragmentData(data, this.maxFragmentSize);
    const fragCount = fragments.length;

    const results = [];
    for (let fragIndex = 0; fragIndex < fragments.length; fragIndex++) {
      const fragData = fragments[fragIndex];

      // Create fragment with header
      const plaintext = createFragment(packetId, fragIndex, fragCount, fragData);

      // Encrypt with SealedBox
      const encrypted = encryptFragment(plaintext, this.serverPubkey);

      // Create DNS query name
      const dnsName = createDnsQuery(encrypted, this.domain);

      // Optionally send query
      const success = sendQueries ? await sendDnsQuery(dnsName) : true;
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
    const results = await this.sendData(data, false);
    return results.map(([dnsName, _]) => dnsName);
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
  -k, --key <public_key>     Server public key (mj_pub_... format)
  -d, --domain <domain>      DNS domain suffix (e.g., .asd.qwe)

Optional arguments:
  -f, --file <path>          Input file path (use "-" for stdin, default: stdin)
  -v, --verbose              Enable verbose output to stderr

Examples:
  echo "Hello" | mumbojumbo-client -k mj_pub_abc123... -d .asd.qwe
  mumbojumbo-client -k mj_pub_abc123... -d .asd.qwe -f message.txt
  mumbojumbo-client -k mj_pub_abc123... -d .asd.qwe -v
      `);
      process.exit(0);
    }
  }

  if (!key || !domain) {
    console.error('Error: -k/--key and -d/--domain are required');
    console.error('Use --help for usage information');
    process.exit(1);
  }

  // Parse server public key
  let serverPubkeyBytes;
  try {
    serverPubkeyBytes = parseKeyHex(key);
  } catch (err) {
    console.error(`Error parsing key: ${err.message}`);
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

  // Create client
  let client;
  try {
    client = new MumbojumboClient(serverPubkeyBytes, domain);
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
    results = await client.sendData(data, true);
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
      const plaintextLen = 12 + fragDataLen;
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
  parseKeyHex,
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
