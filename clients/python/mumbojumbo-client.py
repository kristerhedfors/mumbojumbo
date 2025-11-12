#!/usr/bin/env python3
"""
Mumbojumbo DNS Client - Reference Implementation

Sends data through DNS queries using the mumbojumbo protocol.
Minimalist design: only requires pynacl for crypto.
"""

import sys
import argparse
import base64
import struct
import random
import subprocess
import nacl.public


MAX_FRAG_DATA_LEN = 80
DNS_LABEL_MAX_LEN = 63


def parse_key_hex(key_str):
    """Parse mj_cli_<hex> format key to bytes."""
    if not key_str.startswith('mj_cli_'):
        raise ValueError('Key must start with "mj_cli_"')
    hex_key = key_str[7:]
    if len(hex_key) != 64:
        raise ValueError(f'Invalid hex key length: expected 64, got {len(hex_key)}')
    try:
        return bytes.fromhex(hex_key)
    except ValueError as e:
        raise ValueError(f'Invalid hex key: {e}')


def base32_encode(data):
    """Encode to lowercase base32 without padding."""
    return base64.b32encode(data).replace(b'=', b'').lower().decode('ascii')


def split_to_labels(data, max_len=DNS_LABEL_MAX_LEN):
    """Split string into DNS label chunks of max_len characters."""
    return [data[i:i+max_len] for i in range(0, len(data), max_len)]


def create_fragment(packet_id, frag_index, frag_count, frag_data):
    """
    Create fragment with 12-byte header.

    Header format (big-endian):
    - packet_id: u16 (0-65535)
    - frag_index: u32 (0-based fragment index, up to 4.3 billion)
    - frag_count: u32 (total fragments in packet, up to 4.3 billion)
    - frag_data_len: u16 (length of fragment data, 0-65535)
    """
    if not (0 <= packet_id <= 0xFFFF):
        raise ValueError(f'packet_id out of range: {packet_id}')
    if not (0 <= frag_index < frag_count):
        raise ValueError(f'Invalid frag_index {frag_index} for frag_count {frag_count}')
    if not (0 <= frag_count <= 0xFFFFFFFF):
        raise ValueError(f'frag_count out of u32 range: {frag_count}')
    if len(frag_data) > MAX_FRAG_DATA_LEN:
        raise ValueError(f'Fragment data too large: {len(frag_data)} > {MAX_FRAG_DATA_LEN}')

    header = struct.pack('!HIIH', packet_id, frag_index, frag_count, len(frag_data))
    return header + frag_data


def encrypt_fragment(plaintext, server_client_key):
    """Encrypt fragment using NaCl SealedBox (anonymous encryption)."""
    sealedbox = nacl.public.SealedBox(server_client_key)
    return bytes(sealedbox.encrypt(plaintext))


def create_dns_query(encrypted, domain):
    """
    Create DNS query name from encrypted fragment.

    Process:
    1. Base32 encode encrypted data
    2. Split into 63-character DNS labels
    3. Append domain suffix
    """
    b32 = base32_encode(encrypted)
    labels = split_to_labels(b32, DNS_LABEL_MAX_LEN)
    return '.'.join(labels) + domain


def send_dns_query(dns_name):
    """Send DNS query using dig command."""
    try:
        result = subprocess.run(
            ['dig', '+short', dns_name],
            capture_output=True,
            timeout=5,
            text=True
        )
        return result.returncode == 0
    except subprocess.TimeoutExpired:
        return False
    except FileNotFoundError:
        # dig not found, try with host command
        try:
            result = subprocess.run(
                ['host', dns_name],
                capture_output=True,
                timeout=5,
                text=True
            )
            return result.returncode == 0
        except:
            return False
    except Exception:
        return False


def fragment_data(data, max_fragment_size=MAX_FRAG_DATA_LEN):
    """Split data into fragments of max_fragment_size bytes."""
    if not data:
        # Send at least one empty fragment
        return [b'']
    return [data[i:i+max_fragment_size]
            for i in range(0, len(data), max_fragment_size)]


class MumbojumboClient:
    """
    Modular Mumbojumbo DNS client for sending data via DNS queries.

    This class provides a clean programmatic interface for:
    - Sending single or multi-fragment messages
    - Encrypting data with server's public key
    - Generating DNS queries
    - Optionally sending queries to DNS resolver
    - Automatic packet ID management
    """

    def __init__(self, server_client_key, domain, max_fragment_size=MAX_FRAG_DATA_LEN):
        """
        Initialize client.

        Args:
            server_client_key: Server's public key (bytes or nacl.public.PublicKey)
            domain: DNS domain suffix (e.g., '.asd.qwe')
            max_fragment_size: Maximum bytes per fragment (default: 80)
        """
        if isinstance(server_client_key, bytes):
            self.server_client_key = nacl.public.PublicKey(server_client_key)
        else:
            self.server_client_key = server_client_key

        self.domain = domain if domain.startswith('.') else '.' + domain
        self.max_fragment_size = max_fragment_size
        self._next_packet_id = random.randint(0, 0xFFFF)

    def _get_next_packet_id(self):
        """Get next packet ID and increment counter (wraps at 0xFFFF)."""
        packet_id = self._next_packet_id
        self._next_packet_id = (self._next_packet_id + 1) & 0xFFFF
        return packet_id

    def send_data(self, data, send_queries=True):
        """
        Send data via DNS queries.

        Args:
            data: Bytes to send
            send_queries: If True, actually send DNS queries; if False, just return queries

        Returns:
            List of (dns_query, success) tuples
        """
        packet_id = self._get_next_packet_id()

        # Fragment data
        fragments = fragment_data(data, self.max_fragment_size)
        frag_count = len(fragments)

        results = []
        for frag_index, frag_data in enumerate(fragments):
            # Create fragment with header
            plaintext = create_fragment(packet_id, frag_index, frag_count, frag_data)

            # Encrypt with SealedBox
            encrypted = encrypt_fragment(plaintext, self.server_client_key)

            # Create DNS query name
            dns_name = create_dns_query(encrypted, self.domain)

            # Optionally send query
            success = send_dns_query(dns_name) if send_queries else True
            results.append((dns_name, success))

        return results

    def generate_queries(self, data):
        """
        Generate DNS queries without sending them.

        Args:
            data: Bytes to send

        Returns:
            List of DNS query strings
        """
        results = self.send_data(data, send_queries=False)
        return [dns_name for dns_name, _ in results]


def main():
    parser = argparse.ArgumentParser(
        description='Mumbojumbo DNS Client - Send data via DNS queries',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog='''
examples:
  # Send from stdin
  echo "Hello World" | %(prog)s -k mj_cli_abc123... -d .asd.qwe

  # Send from file
  %(prog)s -k mj_cli_abc123... -d .asd.qwe -f message.txt

  # Send from stdin (explicit)
  %(prog)s -k mj_cli_abc123... -d .asd.qwe -f -
        '''
    )
    parser.add_argument(
        '-k', '--key',
        required=True,
        help='Server public key in mj_cli_<hex> format'
    )
    parser.add_argument(
        '-d', '--domain',
        required=True,
        help='DNS domain suffix (e.g., .asd.qwe)'
    )
    parser.add_argument(
        '-f', '--file',
        default='-',
        help='Input file path (use "-" for stdin, default: stdin)'
    )
    parser.add_argument(
        '-v', '--verbose',
        action='store_true',
        help='Verbose output'
    )

    args = parser.parse_args()

    # Parse server public key
    try:
        server_client_key_bytes = parse_key_hex(args.key)
    except Exception as e:
        print(f"Error parsing key: {e}", file=sys.stderr)
        return 1

    # Validate domain
    domain = args.domain
    if not domain.startswith('.'):
        print(f"Warning: domain should start with '.', got '{domain}'", file=sys.stderr)
        print(f"         Prepending '.' automatically", file=sys.stderr)
        domain = '.' + domain

    # Read input data
    try:
        if args.file == '-':
            data = sys.stdin.buffer.read()
        else:
            with open(args.file, 'rb') as f:
                data = f.read()
    except Exception as e:
        print(f"Error reading input: {e}", file=sys.stderr)
        return 1

    if args.verbose:
        print(f"Read {len(data)} bytes of input", file=sys.stderr)

    # Create client
    try:
        client_obj = MumbojumboClient(server_client_key_bytes, domain)
    except Exception as e:
        print(f"Error initializing client: {e}", file=sys.stderr)
        return 1

    if args.verbose:
        frag_count = len(fragment_data(data, MAX_FRAG_DATA_LEN))
        print(f"Split into {frag_count} fragment(s)", file=sys.stderr)
        print("", file=sys.stderr)

    # Send data
    try:
        results = client_obj.send_data(data, send_queries=True)
    except Exception as e:
        print(f"Error sending data: {e}", file=sys.stderr)
        if args.verbose:
            import traceback
            traceback.print_exc(file=sys.stderr)
        return 1

    # Process results
    success_count = 0
    for frag_index, (dns_name, success) in enumerate(results):
        # Output query for inspection
        print(dns_name)

        if success:
            success_count += 1

        if args.verbose:
            frag_count = len(results)
            print(f"Fragment {frag_index + 1}/{frag_count}:", file=sys.stderr)

            # Calculate sizes for display
            frag_data_len = len(data[frag_index * MAX_FRAG_DATA_LEN:(frag_index + 1) * MAX_FRAG_DATA_LEN])
            plaintext_len = 12 + frag_data_len  # 12-byte header (u16 + u32 + u32 + u16)
            encrypted_len = plaintext_len + 48  # SealedBox adds ~48 bytes overhead

            print(f"  Data length: {frag_data_len} bytes", file=sys.stderr)
            print(f"  Plaintext length: {plaintext_len} bytes", file=sys.stderr)
            print(f"  Encrypted length: {encrypted_len} bytes", file=sys.stderr)
            print(f"  DNS name length: {len(dns_name)} chars", file=sys.stderr)
            print(f"  Sending query...", file=sys.stderr)

            if success:
                print(f"  ✓ Sent successfully", file=sys.stderr)
            else:
                print(f"  ✗ Send failed (DNS query timed out or failed)", file=sys.stderr)

            print("", file=sys.stderr)

    if args.verbose:
        print(f"Sent {success_count}/{len(results)} fragment(s) successfully", file=sys.stderr)

    return 0 if success_count == len(results) else 1


if __name__ == '__main__':
    sys.exit(main())
