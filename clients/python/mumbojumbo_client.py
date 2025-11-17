#!/usr/bin/env python3
"""
Mumbojumbo DNS Client v2.0 - Reference Implementation

Sends key-value pairs through DNS queries using mumbojumbo v2.0 protocol.
Pure Python implementation using only standard library for crypto.

Protocol: ChaCha20-Poly1305 encryption with dual-layer authentication
Encoding: Base36 (40 bytes → 63 characters per DNS label)

Usage as library:
    from mumbojumbo_client import MumbojumboClient

    # Initialize with client key (keys are derived internally)
    client = MumbojumboClient(
        client_key='mj_cli_abc123...',
        domain='.example.com'
    )

    # Send key-value pair
    client.send(key=b'filename.txt', value=b'Hello, World!')

    # Send value only (no key)
    client.send(value=b'Data without key')

Usage from CLI:
    ./mumbojumbo_client.py --client-key mj_cli_... -d .example.com -k mykey -v myvalue

    echo "data" | ./mumbojumbo_client.py --client-key mj_cli_... -d .example.com
"""

import sys
import os
import argparse
import struct
import secrets
import subprocess


# ============================================================================
# Cryptography (ChaCha20, Poly1305, Base36) - copied from server
# ============================================================================

def rotl32(v, c):
    """Rotate left: 32-bit value v by c bits."""
    return ((v << c) & 0xffffffff) | (v >> (32 - c))


def quarter_round(state, a, b, c, d):
    """ChaCha20 quarter round."""
    state[a] = (state[a] + state[b]) & 0xffffffff
    state[d] ^= state[a]
    state[d] = rotl32(state[d], 16)
    state[c] = (state[c] + state[d]) & 0xffffffff
    state[b] ^= state[c]
    state[b] = rotl32(state[b], 12)
    state[a] = (state[a] + state[b]) & 0xffffffff
    state[d] ^= state[a]
    state[d] = rotl32(state[d], 8)
    state[c] = (state[c] + state[d]) & 0xffffffff
    state[b] ^= state[c]
    state[b] = rotl32(state[b], 7)


def chacha20_block(key, counter, nonce):
    """Generate 64-byte ChaCha20 keystream block."""
    constants = [0x61707865, 0x3320646e, 0x79622d32, 0x6b206574]
    key_words = list(struct.unpack('<8I', key))
    counter_word = counter & 0xffffffff
    nonce_words = list(struct.unpack('<3I', nonce))
    state = constants + key_words + [counter_word] + nonce_words
    working_state = state[:]
    for _ in range(10):
        quarter_round(working_state, 0, 4, 8, 12)
        quarter_round(working_state, 1, 5, 9, 13)
        quarter_round(working_state, 2, 6, 10, 14)
        quarter_round(working_state, 3, 7, 11, 15)
        quarter_round(working_state, 0, 5, 10, 15)
        quarter_round(working_state, 1, 6, 11, 12)
        quarter_round(working_state, 2, 7, 8, 13)
        quarter_round(working_state, 3, 4, 9, 14)
    for i in range(16):
        working_state[i] = (working_state[i] + state[i]) & 0xffffffff
    return struct.pack('<16I', *working_state)


def chacha20_encrypt(key, nonce, plaintext, counter=0):
    """Encrypt/decrypt with ChaCha20."""
    if len(nonce) == 8:
        nonce = nonce + b'\x00\x00\x00\x00'
    elif len(nonce) != 12:
        raise ValueError(f"Nonce must be 8 or 12 bytes, got {len(nonce)}")
    if len(key) != 32:
        raise ValueError(f"Key must be 32 bytes, got {len(key)}")
    keystream = b''
    blocks_needed = (len(plaintext) + 63) // 64
    for i in range(blocks_needed):
        keystream += chacha20_block(key, counter + i, nonce)
    keystream = keystream[:len(plaintext)]
    return bytes(p ^ k for p, k in zip(plaintext, keystream))


def poly1305_mac(key, msg):
    """Compute Poly1305 MAC."""
    if len(key) != 32:
        raise ValueError(f"Key must be 32 bytes, got {len(key)}")
    r_bytes = key[:16]
    s_bytes = key[16:32]
    r = int.from_bytes(r_bytes, 'little')
    r &= 0x0ffffffc0ffffffc0ffffffc0fffffff
    s = int.from_bytes(s_bytes, 'little')
    p = (1 << 130) - 5
    accumulator = 0
    for i in range(0, len(msg), 16):
        block = msg[i:i+16]
        if len(block) == 16:
            n = int.from_bytes(block + b'\x01', 'little')
        else:
            n = int.from_bytes(block + b'\x01', 'little')
        accumulator = ((accumulator + n) * r) % p
    accumulator = (accumulator + s) % (1 << 128)
    return accumulator.to_bytes(16, 'little')


BASE36_ALPHABET = '0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ'


def base36_encode(data):
    """Encode bytes to base36 string."""
    if not data:
        return '0'
    num = int.from_bytes(data, 'big')
    if num == 0:
        return '0'
    result = []
    while num > 0:
        num, remainder = divmod(num, 36)
        result.append(BASE36_ALPHABET[remainder])
    return ''.join(reversed(result))


# ============================================================================
# Protocol Constants
# ============================================================================

BINARY_PACKET_SIZE = 40
BASE36_PACKET_SIZE = 63
PACKET_ID_SIZE = 4  # u32, first in fragment, unencrypted
FRAGMENT_FLAGS_SIZE = 4  # flags+index (4B)
FRAGMENT_MAC_SIZE = 4
FRAGMENT_PAYLOAD_SIZE = 28  # message chunk (encrypted along with flags+mac)
MESSAGE_NONCE_SIZE = 8
MESSAGE_INTEGRITY_SIZE = 8

FIRST_FLAG_MASK = 0x80000000
MORE_FLAG_MASK = 0x40000000
INDEX_MASK = 0x3FFFFFFF


# ============================================================================
# Key Encoding
# ============================================================================

def decode_mumbojumbo_key(key_str):
    """
    Decode mumbojumbo key string to bytes.

    Args:
        key_str: mj_cli_<64_hex_chars> or raw hex

    Returns:
        bytes: 32-byte key
    """
    if key_str.startswith('mj_'):
        parts = key_str.split('_')
        if len(parts) == 3:
            hex_str = parts[2]
        else:
            hex_str = key_str
    else:
        hex_str = key_str

    try:
        key_bytes = bytes.fromhex(hex_str)
    except ValueError as e:
        raise ValueError(f'Invalid mumbojumbo key: {e}')

    if len(key_bytes) != 32:
        raise ValueError(f'Key must be 32 bytes, got {len(key_bytes)}')

    return key_bytes


def derive_keys(client_key):
    """
    Derive encryption, authentication, and fragment keys from client key.

    Args:
        client_key: bytes, 32-byte master key

    Returns:
        tuple: (enc_key, auth_key, frag_key), each 32 bytes
    """
    if len(client_key) != 32:
        raise ValueError(f'Client key must be 32 bytes, got {len(client_key)}')

    # Derive 32-byte keys by concatenating two 16-byte MACs
    enc_key = poly1305_mac(client_key, b'enc') + poly1305_mac(client_key, b'enc2')
    auth_key = poly1305_mac(client_key, b'auth') + poly1305_mac(client_key, b'auth2')
    frag_key = poly1305_mac(client_key, b'frag') + poly1305_mac(client_key, b'frag2')

    return enc_key, auth_key, frag_key


# ============================================================================
# Client Implementation
# ============================================================================

class MumbojumboClient:
    """
    Mumbojumbo v2.0 DNS client.

    Encrypts and fragments key-value pairs into DNS queries.
    """

    def __init__(self, client_key, domain='.example.com', resolver='8.8.8.8'):
        """
        Initialize client.

        Args:
            client_key: str or bytes, mumbojumbo client key (mj_cli_...)
            domain: str, DNS domain suffix (e.g., '.example.com')
            resolver: str, DNS resolver to use
        """
        # Decode key if string
        if isinstance(client_key, str):
            client_key = decode_mumbojumbo_key(client_key)

        # Derive encryption, auth, and fragment keys from client key
        self.enc_key, self.auth_key, self.frag_key = derive_keys(client_key)

        self.domain = domain
        self.resolver = resolver

        # Packet ID counter (u32: 0-4294967295, wraps)
        self._next_packet_id = secrets.randbits(32)

    def _encrypt_message(self, plaintext):
        """
        Encrypt complete message (before fragmentation).

        Args:
            plaintext: bytes, complete message

        Returns:
            bytes: [nonce (8B)][integrity (8B)][encrypted_kv]
        """
        # Generate 8-byte nonce
        nonce = os.urandom(MESSAGE_NONCE_SIZE)

        # Encrypt with ChaCha20
        encrypted_kv = chacha20_encrypt(self.enc_key, nonce, plaintext)

        # Compute 8-byte integrity MAC
        integrity_full = poly1305_mac(self.auth_key, nonce + encrypted_kv)
        integrity = integrity_full[:MESSAGE_INTEGRITY_SIZE]

        # Build complete message
        message = nonce + integrity + encrypted_kv
        return message

    def _create_fragment(self, packet_id, frag_index, is_first, has_more, frag_data):
        """
        Create a 40-byte binary fragment with dual-layer encryption.

        Args:
            packet_id: u32
            frag_index: int (30-bit)
            is_first: bool
            has_more: bool
            frag_data: bytes (up to 28 bytes)

        Returns:
            bytes: 40-byte binary packet

        Structure (40 bytes total):
            Packet ID (4B): u32, big-endian, UNENCRYPTED
            MAC (4B): Poly1305 over encrypted portion, UNENCRYPTED
            Encrypted (32B): ChaCha20 encrypted with nonce = packet_id * 3
                - flags+index (4B)
                - payload (28B): fragment data
        """
        # Build flags+index (4B)
        flags = 0
        if is_first:
            flags |= FIRST_FLAG_MASK
        if has_more:
            flags |= MORE_FLAG_MASK
        flags |= (frag_index & INDEX_MASK)
        flags_bytes = struct.pack('!I', flags)

        # Build payload: fragment data only (28B)
        payload = frag_data[:FRAGMENT_PAYLOAD_SIZE]

        # Pad to 28 bytes
        if len(payload) < FRAGMENT_PAYLOAD_SIZE:
            payload += b'\x00' * (FRAGMENT_PAYLOAD_SIZE - len(payload))

        # Assemble inner packet (to be encrypted): flags + payload
        inner = flags_bytes + payload
        assert len(inner) == 32

        # Encrypt inner packet with ChaCha20
        # Nonce = packet_id (4 bytes) repeated 3 times = 12 bytes
        packet_id_bytes = struct.pack('!I', packet_id)
        nonce = packet_id_bytes * 3
        encrypted_inner = chacha20_encrypt(self.enc_key, nonce, inner)

        # Compute 4-byte fragment MAC over encrypted portion (validate before decrypt)
        mac_full = poly1305_mac(self.frag_key, encrypted_inner)
        mac = mac_full[:4]

        # Assemble final packet: packet_id + mac + encrypted_inner
        packet = packet_id_bytes + mac + encrypted_inner
        assert len(packet) == BINARY_PACKET_SIZE
        return packet

    def _create_dns_query(self, binary_packet):
        """
        Encode 40-byte binary packet to DNS query string.

        Args:
            binary_packet: bytes, 40 bytes

        Returns:
            str: <63-char-base36>.<domain>
        """
        # Base36 encode
        base36_str = base36_encode(binary_packet)

        # Pad to 63 characters
        if len(base36_str) < BASE36_PACKET_SIZE:
            base36_str = '0' * (BASE36_PACKET_SIZE - len(base36_str)) + base36_str

        # Build DNS query
        dns_query = base36_str + self.domain
        return dns_query

    def generate_queries(self, key=None, value=None):
        """
        Generate DNS queries for a key-value pair.

        Args:
            key: bytes or None, key data
            value: bytes, value data

        Returns:
            list of str: DNS query names
        """
        if value is None:
            raise ValueError('Value cannot be None')

        # Handle key
        if key is None:
            key = b''

        # Build plaintext: [key_length (1B)][key_data][value_data]
        key_length = len(key)
        if key_length > 255:
            raise ValueError(f'Key too long: {key_length} bytes (max 255)')

        plaintext = bytes([key_length]) + key + value

        # Encrypt message ONCE
        message = self._encrypt_message(plaintext)

        # Fragment into 28-byte chunks
        packet_id = self._next_packet_id
        self._next_packet_id = (self._next_packet_id + 1) & 0xFFFFFFFF

        queries = []
        offset = 0

        frag_index = 0
        while offset < len(message):
            frag_data = message[offset:offset + FRAGMENT_PAYLOAD_SIZE]
            is_first = (frag_index == 0)
            has_more = (offset + FRAGMENT_PAYLOAD_SIZE < len(message))

            # Create binary fragment
            binary_packet = self._create_fragment(packet_id, frag_index, is_first, has_more, frag_data)

            # Encode to DNS query
            dns_query = self._create_dns_query(binary_packet)
            queries.append(dns_query)

            offset += FRAGMENT_PAYLOAD_SIZE
            frag_index += 1

        return queries

    def send(self, key=None, value=None, delay=0.1):
        """
        Send key-value pair via DNS queries.

        Args:
            key: bytes or None
            value: bytes
            delay: float, delay between queries in seconds

        Returns:
            int: Number of queries sent
        """
        import time

        queries = self.generate_queries(key=key, value=value)

        print(f'Sending {len(queries)} DNS queries...', file=sys.stderr)

        for i, query in enumerate(queries):
            # Send DNS query using dig
            try:
                subprocess.run(
                    ['dig', f'@{self.resolver}', query, '+short'],
                    capture_output=True,
                    timeout=5,
                    check=False
                )
                print(f'  Sent query {i+1}/{len(queries)}: {query[:50]}...', file=sys.stderr)
            except subprocess.TimeoutExpired:
                print(f'  Warning: Query {i+1} timed out', file=sys.stderr)
            except FileNotFoundError:
                print(f'  Error: dig not found. Install with: brew install bind (macOS) or apt-get install dnsutils (Linux)', file=sys.stderr)
                return 0

            if delay > 0 and i < len(queries) - 1:
                time.sleep(delay)

        print(f'Done! Sent {len(queries)} queries.', file=sys.stderr)
        return len(queries)


# ============================================================================
# CLI
# ============================================================================

def main():
    """Main CLI entry point."""
    parser = argparse.ArgumentParser(
        description='Mumbojumbo DNS Client v2.0',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__
    )

    # Key (required, can come from args, config, or env)
    parser.add_argument('--client-key', help='Client key (mj_cli_...) or set MUMBOJUMBO_CLIENT_KEY env var')
    parser.add_argument('--config', help='Config file path')

    # Network
    parser.add_argument('-d', '--domain', help='DNS domain suffix (e.g., .example.com) or set MUMBOJUMBO_DOMAIN env var')
    parser.add_argument('-r', '--resolver', help='DNS resolver or set MUMBOJUMBO_RESOLVER env var (default: 8.8.8.8)')

    # Data
    parser.add_argument('-k', '--key', help='Key (string, will be encoded as UTF-8)')
    parser.add_argument('-v', '--value', help='Value (string, will be encoded as UTF-8)')
    parser.add_argument('--key-file', help='Read key from file (binary)')
    parser.add_argument('--value-file', help='Read value from file (binary)')
    parser.add_argument('-u', '--upload', nargs='+', metavar='FILE', help='Upload files (key=u://<filename>, value=file contents)')

    # Options
    parser.add_argument('--delay', type=float, default=0.1, help='Delay between queries in seconds (default: 0.1)')
    parser.add_argument('--dry-run', action='store_true', help='Generate queries but do not send')

    args = parser.parse_args()

    # Get client key from args, config, or environment
    client_key = args.client_key

    # Try config file if not provided via args
    if not client_key and args.config:
        try:
            with open(args.config, 'r') as f:
                for line in f:
                    line = line.strip()
                    if line.startswith('client-key'):
                        parts = line.split('=', 1)
                        if len(parts) == 2:
                            client_key = parts[1].strip()
                            break
        except FileNotFoundError:
            print(f'Warning: Config file {args.config} not found', file=sys.stderr)

    # Try environment variable if still not provided
    if not client_key:
        client_key = os.environ.get('MUMBOJUMBO_CLIENT_KEY')

    if not client_key:
        parser.error('Client key required. Use --client-key, config file, or MUMBOJUMBO_CLIENT_KEY env var.')

    # Get domain from args or environment (required)
    domain = args.domain or os.environ.get('MUMBOJUMBO_DOMAIN')
    if not domain:
        parser.error('Domain required. Use -d/--domain or set MUMBOJUMBO_DOMAIN env var.')

    # Get resolver from args or environment (optional, default 8.8.8.8)
    resolver = args.resolver or os.environ.get('MUMBOJUMBO_RESOLVER', '8.8.8.8')

    # Get key
    if args.key_file:
        with open(args.key_file, 'rb') as f:
            key = f.read()
    elif args.key:
        key = args.key.encode('utf-8')
    else:
        key = None

    # Get value (not required if uploading files)
    value = None
    if args.value_file:
        with open(args.value_file, 'rb') as f:
            value = f.read()
    elif args.value:
        value = args.value.encode('utf-8')
    elif not sys.stdin.isatty():
        # Read from stdin
        value = sys.stdin.buffer.read()
    elif not args.upload:
        parser.error('No value provided. Use -v, --value-file, -u/--upload, or pipe data to stdin.')

    if not value and not args.upload:
        parser.error('Value cannot be empty')

    # Create client
    try:
        client = MumbojumboClient(
            client_key=client_key,
            domain=domain,
            resolver=resolver
        )
    except ValueError as e:
        print(f'Error: {e}', file=sys.stderr)
        return 1

    # Handle file uploads if -u/--upload specified
    if args.upload:
        total_queries = 0
        for filepath in args.upload:
            # Read file contents
            try:
                with open(filepath, 'rb') as f:
                    file_contents = f.read()
            except FileNotFoundError:
                print(f'Error: File not found: {filepath}', file=sys.stderr)
                return 1
            except IOError as e:
                print(f'Error reading {filepath}: {e}', file=sys.stderr)
                return 1

            # Construct key as u://<filename>
            filename = os.path.basename(filepath)
            upload_key = f'u://{filename}'.encode('utf-8')

            if args.dry_run:
                queries = client.generate_queries(key=upload_key, value=file_contents)
                print(f'File {filepath} -> {len(queries)} queries (dry run):', file=sys.stderr)
                for i, query in enumerate(queries):
                    print(f'{i+1}. {query}')
            else:
                print(f'Uploading {filepath} as u://{filename}...', file=sys.stderr)
                count = client.send(key=upload_key, value=file_contents, delay=args.delay)
                total_queries += count

        if args.dry_run:
            return 0
        return 0 if total_queries > 0 else 1

    # Generate queries
    queries = client.generate_queries(key=key, value=value)

    if args.dry_run:
        print(f'Generated {len(queries)} queries (dry run):', file=sys.stderr)
        for i, query in enumerate(queries):
            print(f'{i+1}. {query}')
        return 0

    # Send queries
    count = client.send(key=key, value=value, delay=args.delay)

    return 0 if count > 0 else 1


if __name__ == '__main__':
    sys.exit(main())
