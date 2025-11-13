#!/usr/bin/env node
/**
 * Comprehensive tests for Node.js mumbojumbo client
 *
 * Mirrors the 43 tests from the Python implementation.
 * Run with: node --test test-mumbojumbo-client.js
 */

const { test, describe } = require('node:test');
const assert = require('node:assert/strict');
const nacl = require('tweetnacl');
const sealedBox = require('tweetnacl-sealedbox-js');
const { spawn } = require('child_process');
const fs = require('fs');
const path = require('path');

const {
  base32Encode,
  splitToLabels,
  createFragment,
  encryptFragment,
  createDnsQuery,
  fragmentData,
  MumbojumboClient,
  MAX_FRAG_DATA_LEN,
  DNS_LABEL_MAX_LEN
} = require('./mumbojumbo-client.js');

// Test fixtures
const TEST_KEYPAIR = nacl.box.keyPair();
const TEST_SERVER_PUBKEY = TEST_KEYPAIR.publicKey;
const TEST_SERVER_PRIVKEY = TEST_KEYPAIR.secretKey;
const TEST_DOMAIN = '.asd.qwe';

/**
 * Decrypt using NaCl SealedBox
 */
function decryptSealedBox(ciphertext, publicKey, privateKey) {
  return sealedBox.open(ciphertext, publicKey, privateKey);
}

/**
 * Base32 decode (lowercase, no padding)
 */
function base32Decode(encoded) {
  const alphabet = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';
  let bits = 0;
  let value = 0;
  const output = [];

  for (const char of encoded.toUpperCase()) {
    const index = alphabet.indexOf(char);
    if (index === -1) continue;

    value = (value << 5) | index;
    bits += 5;

    if (bits >= 8) {
      output.push((value >>> (bits - 8)) & 0xFF);
      bits -= 8;
    }
  }

  return Buffer.from(output);
}

/**
 * Run CLI command and capture output
 */
async function runCli(args, stdinData = null) {
  return new Promise((resolve, reject) => {
    const child = spawn('node', ['./mumbojumbo-client.js', ...args]);

    const stdout = [];
    const stderr = [];

    child.stdout.on('data', (data) => stdout.push(data));
    child.stderr.on('data', (data) => stderr.push(data));

    child.on('close', (code) => {
      resolve({
        code,
        stdout: Buffer.concat(stdout).toString(),
        stderr: Buffer.concat(stderr).toString()
      });
    });

    child.on('error', reject);

    if (stdinData) {
      child.stdin.write(stdinData);
      child.stdin.end();
    }
  });
}

// ============================================================================
// Test: Key Parsing (via MumbojumboClient constructor)
// ============================================================================

describe('Key Parsing', () => {
  test('parse valid hex key via constructor', () => {
    const validKey = 'mj_cli_' + 'a'.repeat(64);
    const client = new MumbojumboClient(validKey, TEST_DOMAIN);

    assert.ok(client.serverPubkey instanceof Uint8Array);
    assert.equal(client.serverPubkey.length, 32);
    assert.equal(client.serverPubkey[0], 0xaa);
  });

  test('reject key without mj_cli_ prefix', () => {
    assert.throws(() => {
      new MumbojumboClient('a'.repeat(64), TEST_DOMAIN);
    }, /must start with "mj_cli_"/);
  });

  test('reject key with wrong hex length', () => {
    assert.throws(() => {
      new MumbojumboClient('mj_cli_' + 'a'.repeat(32), TEST_DOMAIN);
    }, /Invalid hex key length/);
  });

  test('reject key with invalid hex characters', () => {
    assert.throws(() => {
      new MumbojumboClient('mj_cli_' + 'z'.repeat(64), TEST_DOMAIN);
    }, /Invalid hex characters/);
  });
});

// ============================================================================
// Test: Base32 Encoding
// ============================================================================

describe('Base32 Encoding', () => {
  test('encode basic data', () => {
    const data = Buffer.from('hello');
    const encoded = base32Encode(data);

    assert.equal(encoded, 'nbswy3dp');
  });

  test('encode empty data', () => {
    const encoded = base32Encode(Buffer.alloc(0));
    assert.equal(encoded, '');
  });

  test('encode produces lowercase', () => {
    const data = Buffer.from('TEST');
    const encoded = base32Encode(data);

    assert.equal(encoded, encoded.toLowerCase());
  });

  test('encode has no padding', () => {
    const data = Buffer.from('hello world');
    const encoded = base32Encode(data);

    assert.ok(!encoded.includes('='));
  });

  test('encode/decode round-trip', () => {
    const original = Buffer.from('Round trip test data!');
    const encoded = base32Encode(original);
    const decoded = base32Decode(encoded);

    assert.deepEqual(decoded, original);
  });
});

// ============================================================================
// Test: DNS Label Splitting
// ============================================================================

describe('DNS Label Splitting', () => {
  test('split short string', () => {
    const labels = splitToLabels('abc');
    assert.deepEqual(labels, ['abc']);
  });

  test('split exactly 63 chars', () => {
    const data = 'a'.repeat(63);
    const labels = splitToLabels(data);
    assert.deepEqual(labels, [data]);
  });

  test('split long string', () => {
    const data = 'a'.repeat(100);
    const labels = splitToLabels(data);

    assert.equal(labels.length, 2);
    assert.equal(labels[0].length, 63);
    assert.equal(labels[1].length, 37);
  });

  test('split empty string', () => {
    const labels = splitToLabels('');
    assert.deepEqual(labels, []);
  });

  test('split with custom max length', () => {
    const labels = splitToLabels('abcdefgh', 3);
    assert.deepEqual(labels, ['abc', 'def', 'gh']);
  });
});

// ============================================================================
// Test: Fragment Creation
// ============================================================================

describe('Fragment Creation', () => {
  test('create basic fragment', () => {
    const fragData = Buffer.from('test');
    const frag = createFragment(100, 0, 1, fragData);

    assert.equal(frag.length, 18 + 4);

    // Parse header (18 bytes: u64 packet_id, u32 frag_index, u32 frag_count, u16 frag_data_len)
    const packetIdHigh = frag.readUInt32BE(0);
    const packetIdLow = frag.readUInt32BE(4);
    const packetId = packetIdHigh * 0x100000000 + packetIdLow;
    const fragIndex = frag.readUInt32BE(8);
    const fragCount = frag.readUInt32BE(12);
    const dataLen = frag.readUInt16BE(16);

    assert.equal(packetId, 100);
    assert.equal(fragIndex, 0);
    assert.equal(fragCount, 1);
    assert.equal(dataLen, 4);
    assert.deepEqual(frag.slice(18), fragData);
  });

  test('create multi-fragment packet', () => {
    const fragData = Buffer.from('part1');
    const frag = createFragment(200, 2, 5, fragData);

    const fragIndex = frag.readUInt32BE(8);
    const fragCount = frag.readUInt32BE(12);

    assert.equal(fragIndex, 2);
    assert.equal(fragCount, 5);
  });

  test('create empty fragment', () => {
    const frag = createFragment(1, 0, 1, Buffer.alloc(0));

    assert.equal(frag.length, 18);
    assert.equal(frag.readUInt16BE(16), 0);
  });

  test('reject oversized fragment', () => {
    const oversized = Buffer.alloc(MAX_FRAG_DATA_LEN + 1);

    assert.throws(() => {
      createFragment(1, 0, 1, oversized);
    }, /Fragment data too large/);
  });

  test('reject invalid packet_id', () => {
    assert.throws(() => {
      createFragment(-1, 0, 1, Buffer.from('test'));
    }, /packet_id out of range/);

    // u64 max is Number.MAX_SAFE_INTEGER in JavaScript
    assert.throws(() => {
      createFragment(Number.MAX_SAFE_INTEGER + 1, 0, 1, Buffer.from('test'));
    }, /packet_id out of range/);
  });

  test('reject invalid frag_index', () => {
    assert.throws(() => {
      createFragment(1, -1, 1, Buffer.from('test'));
    }, /Invalid frag_index/);

    assert.throws(() => {
      createFragment(1, 5, 5, Buffer.from('test'));
    }, /Invalid frag_index/);
  });

  test('support u32 frag_count', () => {
    const largeCount = 0xFFFFFFFF;
    const frag = createFragment(1, 0, largeCount, Buffer.from('test'));

    const fragCount = frag.readUInt32BE(12);
    assert.equal(fragCount, largeCount);
  });

  test('support u32 frag_index', () => {
    const largeIndex = 1000000;
    const frag = createFragment(1, largeIndex, largeIndex + 1, Buffer.from('test'));

    const fragIndex = frag.readUInt32BE(8);
    assert.equal(fragIndex, largeIndex);
  });
});

// ============================================================================
// Test: Data Fragmentation
// ============================================================================

describe('Data Fragmentation', () => {
  test('fragment small data', () => {
    const data = Buffer.from('small');
    const fragments = fragmentData(data);

    assert.equal(fragments.length, 1);
    assert.deepEqual(fragments[0], data);
  });

  test('fragment exactly max size', () => {
    const data = Buffer.alloc(MAX_FRAG_DATA_LEN);
    const fragments = fragmentData(data);

    assert.equal(fragments.length, 1);
    assert.equal(fragments[0].length, MAX_FRAG_DATA_LEN);
  });

  test('fragment overflow', () => {
    const data = Buffer.alloc(MAX_FRAG_DATA_LEN + 10);
    const fragments = fragmentData(data);

    assert.equal(fragments.length, 2);
    assert.equal(fragments[0].length, MAX_FRAG_DATA_LEN);
    assert.equal(fragments[1].length, 10);
  });

  test('fragment empty data', () => {
    const fragments = fragmentData(Buffer.alloc(0));

    assert.equal(fragments.length, 1);
    assert.equal(fragments[0].length, 0);
  });

  test('fragment large data', () => {
    const data = Buffer.alloc(250);
    const fragments = fragmentData(data);

    const expectedCount = Math.ceil(250 / MAX_FRAG_DATA_LEN);
    assert.equal(fragments.length, expectedCount);
  });
});

// ============================================================================
// Test: Encryption
// ============================================================================

describe('Encryption', () => {
  test('encrypt fragment', () => {
    const plaintext = Buffer.from('secret data');
    const encrypted = encryptFragment(plaintext, TEST_SERVER_PUBKEY);

    assert.ok(encrypted.length > plaintext.length);
    assert.equal(encrypted.length, plaintext.length + 48);
  });

  test('encrypt/decrypt round-trip', () => {
    const plaintext = Buffer.from('test message');

    const encrypted = encryptFragment(plaintext, TEST_SERVER_PUBKEY);
    const decrypted = decryptSealedBox(encrypted, TEST_SERVER_PUBKEY, TEST_SERVER_PRIVKEY);

    assert.deepEqual(Buffer.from(decrypted), plaintext);
  });

  test('encrypt empty data', () => {
    const encrypted = encryptFragment(Buffer.alloc(0), TEST_SERVER_PUBKEY);

    assert.equal(encrypted.length, 48);
  });

  test('encryption produces different outputs', () => {
    const plaintext = Buffer.from('same data');

    const enc1 = encryptFragment(plaintext, TEST_SERVER_PUBKEY);
    const enc2 = encryptFragment(plaintext, TEST_SERVER_PUBKEY);

    assert.notDeepEqual(enc1, enc2);
  });
});

// ============================================================================
// Test: DNS Query Creation
// ============================================================================

describe('DNS Query Creation', () => {
  test('create basic DNS query', () => {
    const encrypted = Buffer.from('a'.repeat(10));
    const query = createDnsQuery(encrypted, TEST_DOMAIN);

    assert.ok(query.endsWith(TEST_DOMAIN));
  });

  test('create query splits long base32', () => {
    const encrypted = Buffer.alloc(100);
    const query = createDnsQuery(encrypted, TEST_DOMAIN);

    const labels = query.replace(TEST_DOMAIN, '').split('.');
    for (const label of labels) {
      assert.ok(label.length <= DNS_LABEL_MAX_LEN);
    }
  });

  test('create query from empty data', () => {
    const query = createDnsQuery(Buffer.alloc(0), TEST_DOMAIN);
    assert.equal(query, TEST_DOMAIN);
  });
});

// ============================================================================
// Test: MumbojumboClient Class
// ============================================================================

describe('MumbojumboClient Class', () => {
  test('initialize client', () => {
    const client = new MumbojumboClient(TEST_SERVER_PUBKEY, TEST_DOMAIN);

    assert.ok(client.serverPubkey);
    assert.equal(client.domain, TEST_DOMAIN);
    assert.equal(client.maxFragmentSize, MAX_FRAG_DATA_LEN);
  });

  test('initialize with Buffer public key', () => {
    const bufferKey = Buffer.from(TEST_SERVER_PUBKEY);
    const client = new MumbojumboClient(bufferKey, TEST_DOMAIN);

    assert.ok(client.serverPubkey instanceof Uint8Array);
  });

  test('auto-prepend dot to domain', () => {
    const client = new MumbojumboClient(TEST_SERVER_PUBKEY, 'asd.qwe');
    assert.equal(client.domain, '.asd.qwe');
  });

  test('generate queries without sending', async () => {
    const client = new MumbojumboClient(TEST_SERVER_PUBKEY, TEST_DOMAIN);
    const queries = await client.generateQueries(Buffer.from('test'));

    assert.ok(Array.isArray(queries));
    assert.equal(queries.length, 1);
    assert.ok(queries[0].endsWith(TEST_DOMAIN));
  });

  test('generate queries only', async () => {
    const client = new MumbojumboClient(TEST_SERVER_PUBKEY, TEST_DOMAIN);
    const queries = await client.generateQueries(Buffer.from('test'));

    assert.ok(Array.isArray(queries));
    assert.equal(queries.length, 1);
    assert.ok(queries[0].endsWith(TEST_DOMAIN));
  });

  test('packet ID increments', async () => {
    const client = new MumbojumboClient(TEST_SERVER_PUBKEY, TEST_DOMAIN);

    const queries1 = await client.generateQueries(Buffer.from('msg1'));
    const queries2 = await client.generateQueries(Buffer.from('msg2'));

    assert.notEqual(queries1[0], queries2[0]);
  });

  test('packet ID wraps at MAX_SAFE_INTEGER', () => {
    const client = new MumbojumboClient(TEST_SERVER_PUBKEY, TEST_DOMAIN);
    client._nextPacketId = Number.MAX_SAFE_INTEGER - 1;

    const id1 = client._getNextPacketId();
    const id2 = client._getNextPacketId();

    assert.equal(id1, Number.MAX_SAFE_INTEGER - 1);
    assert.equal(id2, 0);
  });

  test('multi-fragment message', async () => {
    const client = new MumbojumboClient(TEST_SERVER_PUBKEY, TEST_DOMAIN);
    const largeData = Buffer.alloc(MAX_FRAG_DATA_LEN * 3);

    const queries = await client.generateQueries(largeData);
    assert.equal(queries.length, 3);
  });
});

// ============================================================================
// Test: End-to-End Flow
// ============================================================================

describe('End-to-End Flow', () => {
  test('encrypt and decrypt single fragment', async () => {
    const client = new MumbojumboClient(TEST_SERVER_PUBKEY, TEST_DOMAIN);
    const message = Buffer.from('Hello World');

    const queries = await client.generateQueries(message);
    assert.equal(queries.length, 1);

    const query = queries[0];
    const base32Part = query.replace(TEST_DOMAIN, '').replace(/\./g, '');
    const encrypted = base32Decode(base32Part);
    const decrypted = decryptSealedBox(encrypted, TEST_SERVER_PUBKEY, TEST_SERVER_PRIVKEY);

    const header = Buffer.from(decrypted.slice(0, 18));
    const data = Buffer.from(decrypted.slice(18));

    const dataLen = header.readUInt16BE(16);
    assert.equal(dataLen, message.length);
    assert.deepEqual(data, message);
  });

  test('encrypt and decrypt multi-fragment', async () => {
    const client = new MumbojumboClient(TEST_SERVER_PUBKEY, TEST_DOMAIN);
    const message = Buffer.alloc(MAX_FRAG_DATA_LEN * 2 + 10);
    message.fill(0x42);

    const queries = await client.generateQueries(message);
    assert.equal(queries.length, 3);

    const fragments = [];

    for (const query of queries) {
      const base32Part = query.replace(TEST_DOMAIN, '').replace(/\./g, '');
      const encrypted = base32Decode(base32Part);
      const decrypted = decryptSealedBox(encrypted, TEST_SERVER_PUBKEY, TEST_SERVER_PRIVKEY);

      const header = Buffer.from(decrypted.slice(0, 18));
      const data = Buffer.from(decrypted.slice(18));

      const packetIdHigh = header.readUInt32BE(0);
      const packetIdLow = header.readUInt32BE(4);
      const packetId = packetIdHigh * 0x100000000 + packetIdLow;
      const fragIndex = header.readUInt32BE(8);
      const fragCount = header.readUInt32BE(12);
      const dataLen = header.readUInt16BE(16);

      fragments.push({ packetId, fragIndex, fragCount, data: data.subarray(0, dataLen) });
    }

    assert.equal(fragments.length, 3);
    assert.equal(fragments[0].fragCount, 3);
    assert.equal(fragments[0].fragIndex, 0);
    assert.equal(fragments[1].fragIndex, 1);
    assert.equal(fragments[2].fragIndex, 2);

    const reassembled = Buffer.concat(fragments.map(f => f.data));
    assert.deepEqual(reassembled, message);
  });
});

// ============================================================================
// Test: CLI Interface
// ============================================================================

describe('CLI Interface', () => {
  const testKeyHex = 'mj_cli_' + Buffer.from(TEST_SERVER_PUBKEY).toString('hex');

  test('show help', async () => {
    const result = await runCli(['--help']);

    assert.equal(result.code, 0);
    assert.ok(result.stdout.includes('Usage:'));
    assert.ok(result.stdout.includes('--key'));
    assert.ok(result.stdout.includes('--domain'));
  });

  test('missing required arguments', async () => {
    const result = await runCli([]);

    assert.notEqual(result.code, 0);
    assert.ok(result.stderr.includes('required'));
  });

  test('read from stdin', async () => {
    const result = await runCli([
      '-k', testKeyHex,
      '-d', TEST_DOMAIN
    ], 'test message');

    assert.equal(result.code, 0);
    assert.ok(result.stdout.includes(TEST_DOMAIN));
  });

  test('read from file', async () => {
    const tmpFile = path.join(__dirname, 'test-input.tmp');
    fs.writeFileSync(tmpFile, 'file content');

    try {
      const result = await runCli([
        '-k', testKeyHex,
        '-d', TEST_DOMAIN,
        '-f', tmpFile
      ]);

      assert.equal(result.code, 0);
      assert.ok(result.stdout.includes(TEST_DOMAIN));
    } finally {
      fs.unlinkSync(tmpFile);
    }
  });

  test('verbose mode', async () => {
    const result = await runCli([
      '-k', testKeyHex,
      '-d', TEST_DOMAIN,
      '-v'
    ], 'test');

    assert.equal(result.code, 0);
    assert.ok(result.stderr.includes('bytes'));
  });

  test('invalid key format', async () => {
    const result = await runCli([
      '-k', 'invalid_key',
      '-d', TEST_DOMAIN
    ], 'test');

    assert.notEqual(result.code, 0);
    assert.ok(result.stderr.includes('Error'));
  });
});

console.log('\n✅ All tests defined. Run with: node --test test-mumbojumbo-client.js\n');
