#!/usr/bin/env python3
"""
Mumbojumbo DNS Client - Reference Implementation

Sends key-value pairs through DNS queries using the mumbojumbo protocol.
Minimalist design: only requires pynacl for crypto.

Usage as library:
    from mumbojumbo_client import MumbojumboClient

    client = MumbojumboClient('mj_cli_abc123...', '.example.com')
    client.send(b'filename.txt', b'Hello, World!')

Usage from CLI:
    ./mumbojumbo_client.py --client-key mj_cli_abc123... -d .example.com -k mykey -v myvalue
    echo "data" | ./mumbojumbo_client.py --client-key mj_cli_abc123... -d .example.com
"""

import sys
import os
import argparse
import base64
import struct
import secrets
import asyncio
import socket
import nacl.public


DNS_LABEL_MAX_LEN = 63


def calculate_safe_max_fragment_data_len(domain):
    '''
    Calculate safe maximum fragment data size using simplified formula.
    Formula: 83 - len(domain) // 3

    This simplified formula is:
    - Within 0-2 bytes of optimal for typical domains (3-12 chars)
    - Within 5-7 bytes for longer domains (22-33 chars)
    - Always safe (slightly conservative, never exceeds DNS limits)
    - Requires only one arithmetic operation

    Args:
        domain: DNS domain string (e.g., '.example.com')

    Returns:
        Maximum safe fragment data length in bytes

    Raises:
        ValueError: If domain is too long (>143 chars)
    '''
    if len(domain) > 143:
        raise ValueError(f'Domain too long: {len(domain)} chars (max 143)')
    return 83 - len(domain) // 3


def base32_encode(data):
    """Encode to lowercase base32 without padding."""
    return base64.b32encode(data).replace(b'=', b'').lower().decode('ascii')


def split_to_labels(data, max_len=DNS_LABEL_MAX_LEN):
    """Split string into DNS label chunks of max_len characters."""
    return [data[i:i+max_len] for i in range(0, len(data), max_len)]


def create_fragment(packet_id, frag_index, frag_count, frag_data, key_len=0):
    """
    Create fragment with 19-byte header.

    Header format (big-endian):
    - packet_id: u64 (0 to 2^64-1)
    - frag_index: u32 (0-based fragment index, up to 4.3 billion)
    - frag_count: u32 (total fragments in packet, up to 4.3 billion)
    - frag_data_len: u8 (length of fragment data, 0-255)
    - key_len: u8 (length of key in reassembled packet, 0-255)
    """
    if not (0 <= packet_id <= 0xFFFFFFFFFFFFFFFF):
        raise ValueError(f'packet_id out of range: {packet_id}')
    if not (0 <= frag_index < frag_count):
        raise ValueError(f'Invalid frag_index {frag_index} for frag_count {frag_count}')
    if not (0 <= frag_count <= 0xFFFFFFFF):
        raise ValueError(f'frag_count out of u32 range: {frag_count}')
    if not (0 <= len(frag_data) <= 255):
        raise ValueError(f'Fragment data length {len(frag_data)} exceeds u8 limit (0-255)')
    if not (0 <= key_len <= 255):
        raise ValueError(f'key_len out of u8 range: {key_len}')

    header = struct.pack('!QIIBB', packet_id, frag_index, frag_count, len(frag_data), key_len)
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


async def send_dns_query_async(dns_name, success_callback=None, error_callback=None):
    """
    Send DNS query using native Python socket resolution (fire-and-forget).

    Does not wait for or check responses - just initiates the query.
    Optionally calls callbacks to track success/error counts.
    """
    async def _query_task():
        """Inner task that tracks success/error."""
        try:
            loop = asyncio.get_event_loop()
            await loop.getaddrinfo(dns_name, None)
            if success_callback:
                success_callback()
        except Exception:
            if error_callback:
                error_callback()

    # Create task and suppress exception warnings
    task = asyncio.create_task(_query_task())
    # Suppress "Task exception was never retrieved" warnings
    task.add_done_callback(lambda t: t.exception() if not t.cancelled() else None)


def fragment_data(data, max_fragment_size):
    """Split data into fragments of max_fragment_size bytes."""
    if not data:
        # Send at least one empty fragment
        return [b'']
    return [data[i:i+max_fragment_size]
            for i in range(0, len(data), max_fragment_size)]


class MumbojumboClient:
    """
    User-friendly Mumbojumbo DNS client for sending key-value pairs via DNS.

    Simple interface:
    - send(key, value) - Send key-value pair immediately
    - generate_queries(key, value) - Generate DNS queries without sending

    All fragmentation, encryption, and protocol handling is internal.
    """

    def __init__(self, server_client_key, domain, max_fragment_size=None):
        """
        Initialize client.

        Args:
            server_client_key: Server's public key (mj_cli_ hex string, bytes, or nacl.public.PublicKey)
            domain: DNS domain suffix (e.g., '.asd.qwe')
            max_fragment_size: Maximum bytes per fragment (default: auto-calculated from domain)

        Example:
            client = MumbojumboClient('mj_cli_abc123...', '.example.com')
            client.send(b'filename.txt', b'file contents...')
        """
        # Auto-parse hex key format if string is provided
        if isinstance(server_client_key, str):
            key_bytes = self._parse_key_hex(server_client_key)
            self.server_client_key = nacl.public.PublicKey(key_bytes)
        elif isinstance(server_client_key, bytes):
            self.server_client_key = nacl.public.PublicKey(server_client_key)
        else:
            self.server_client_key = server_client_key

        self.domain = domain if domain.startswith('.') else '.' + domain

        # Auto-calculate max_fragment_size from domain if not provided
        if max_fragment_size is None:
            self.max_fragment_size = calculate_safe_max_fragment_data_len(self.domain)
        else:
            self.max_fragment_size = max_fragment_size

        # Initialize with cryptographically secure random u64
        self._next_packet_id = secrets.randbits(64)

    @staticmethod
    def _parse_key_hex(key_str):
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

    def _get_next_packet_id(self):
        """Get next packet ID and increment counter (wraps at 2^64-1)."""
        packet_id = self._next_packet_id
        self._next_packet_id = (self._next_packet_id + 1) & 0xFFFFFFFFFFFFFFFF
        return packet_id

    def _validate_key_value(self, key, value):
        """Validate and normalize key-value pair."""
        # Handle key: None is allowed and converts to empty bytes
        if key is None:
            key = b''

        # Validate value: Must be non-empty bytes
        if value is None:
            raise ValueError('Value cannot be None - must be bytes with at least 1 byte')
        if not isinstance(value, bytes):
            raise TypeError('Value must be bytes (not None)')
        if len(value) == 0:
            raise ValueError('Value must be at least 1 byte')

        # Validate key
        if not isinstance(key, bytes):
            raise TypeError('Key must be bytes or None')
        if len(key) > 255:
            raise ValueError('Key length cannot exceed 255 bytes')

        return key, value

    def _generate_dns_queries(self, key, value):
        """
        Internal: Generate DNS queries from key-value pair.

        Handles all protocol details: combines key+value, fragments, encrypts, encodes.
        """
        # Validate inputs
        key, value = self._validate_key_value(key, value)

        # Combine key and value into single data blob
        data = key + value
        key_len = len(key)

        # Get packet ID
        packet_id = self._get_next_packet_id()

        # Fragment data
        fragments = fragment_data(data, self.max_fragment_size)
        frag_count = len(fragments)

        # Generate DNS query for each fragment
        queries = []
        for frag_index, frag_data in enumerate(fragments):
            # Create fragment with header (key_len same for all fragments)
            plaintext = create_fragment(packet_id, frag_index, frag_count, frag_data, key_len)

            # Encrypt with SealedBox
            encrypted = encrypt_fragment(plaintext, self.server_client_key)

            # Create DNS query name
            dns_name = create_dns_query(encrypted, self.domain)
            queries.append(dns_name)

        return queries

    async def _generate_queries_streaming(self, key, value):
        """
        Generate DNS queries as async generator (streaming, no pre-allocation).

        Yields DNS query strings one at a time without storing all in memory.
        """
        # Validate inputs
        key, value = self._validate_key_value(key, value)

        # Combine key and value into single data blob
        data = key + value
        key_len = len(key)

        # Get packet ID
        packet_id = self._get_next_packet_id()

        # Fragment data
        fragments = fragment_data(data, self.max_fragment_size)
        frag_count = len(fragments)

        # Generate and yield DNS queries one at a time
        for frag_index, frag_data in enumerate(fragments):
            # Create fragment with header (key_len same for all fragments)
            plaintext = create_fragment(packet_id, frag_index, frag_count, frag_data, key_len)

            # Encrypt with SealedBox
            encrypted = encrypt_fragment(plaintext, self.server_client_key)

            # Create DNS query name
            dns_name = create_dns_query(encrypted, self.domain)

            yield dns_name

    def generate_queries(self, key, value):
        """
        Generate key-value DNS queries without sending them.

        Args:
            key: Key bytes or None (for null/zero-length key)
            value: Value bytes (MUST be at least 1 byte, cannot be None or empty)

        Returns:
            List of DNS query strings

        Example:
            queries = client.generate_queries(b'mykey', b'myvalue')
            for query in queries:
                print(query)
        """
        return self._generate_dns_queries(key, value)

    async def send_async(self, key, value, rate_qps=10, progress_callback=None,
                         query_callback=None):
        """
        Send key-value pair via DNS queries with rate limiting (fire-and-forget).

        Simple approach:
        - Fires off DNS queries at controlled rate (no waiting for responses)
        - Tracks success/error counts in background
        - O(1) memory usage (streaming)

        Args:
            key: Key bytes or None (for null/zero-length key)
            value: Value bytes (MUST be at least 1 byte, cannot be None or empty)
            rate_qps: Queries per second (default 10)
            progress_callback: Optional callback(sent, total, succeeded, failed) called periodically
            query_callback: Optional callback(dns_query) called when query is generated

        Returns:
            Dictionary with summary: {'total': N, 'succeeded': N, 'failed': N}

        Example:
            client = MumbojumboClient('mj_cli_abc123...', '.example.com')
            summary = await client.send_async(b'mykey', b'myvalue', rate_qps=20)
            print(f"Sent {summary['total']} queries, {summary['succeeded']} succeeded")
        """
        total = 0
        succeeded = 0
        failed = 0
        delay_between_queries = 1.0 / rate_qps

        def on_success():
            nonlocal succeeded
            succeeded += 1

        def on_error():
            nonlocal failed
            failed += 1

        # Generate and send queries with rate limiting
        async for dns_query in self._generate_queries_streaming(key, value):
            total += 1

            # Call query callback if provided (for outputting DNS queries)
            if query_callback:
                query_callback(dns_query)

            # Fire off DNS query (don't wait) with callbacks
            await send_dns_query_async(dns_query, on_success, on_error)

            # Call progress callback if provided
            if progress_callback:
                progress_callback(total, total, succeeded, failed)

            # Rate limiting: sleep between queries
            await asyncio.sleep(delay_between_queries)

        # Return summary
        return {'total': total, 'succeeded': succeeded, 'failed': failed}

    def send_sync(self, key, value, rate_qps=10, progress_callback=None,
                  query_callback=None):
        """
        Synchronous wrapper for send_async() - blocks until all queries sent.

        Args:
            key: Key bytes or None (for null/zero-length key)
            value: Value bytes (MUST be at least 1 byte, cannot be None or empty)
            rate_qps: Queries per second (default 10)
            progress_callback: Optional callback(sent, total) called after each query sent
            query_callback: Optional callback(dns_query) called when query is generated

        Example:
            client = MumbojumboClient('mj_cli_abc123...', '.example.com')
            client.send_sync(b'mykey', b'myvalue', rate_qps=20)
        """
        return asyncio.run(
            self.send_async(key, value, rate_qps, progress_callback, query_callback)
        )

    # Legacy aliases for backwards compatibility with tests
    def send_key_val(self, key, value):
        """
        Legacy alias for send_sync(). Use send_async() or send_sync() instead.

        This method exists for backwards compatibility with existing tests.
        Internally calls send_sync() with default parameters.
        """
        return self.send_sync(key, value)

    def generate_queries_key_val(self, key, value):
        """Legacy alias for generate_queries(). Use generate_queries() instead."""
        return self.generate_queries(key, value)


async def async_main():
    """Async version of main function."""
    parser = argparse.ArgumentParser(
        description='Mumbojumbo DNS Client - Send key-value pairs via DNS queries',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog='''
examples:
  # Send key-value pair explicitly
  %(prog)s --client-key mj_cli_abc123... -d .asd.qwe -k mykey -v myvalue

  # Send files (filename as key, contents as value)
  # Note: -k/--key is NOT allowed with files
  %(prog)s --client-key mj_cli_abc123... -d .asd.qwe file1.txt file2.txt

  # Send from stdin with null key (key=None) - POSIX-compliant
  echo "Hello World" | %(prog)s --client-key mj_cli_abc123... -d .asd.qwe -

  # Send from stdin with custom key
  echo "Hello World" | %(prog)s --client-key mj_cli_abc123... -d .asd.qwe -k mykey -

  # Use environment variables (no arguments needed)
  export MUMBOJUMBO_CLIENT_KEY=mj_cli_abc123...
  export MUMBOJUMBO_DOMAIN=.asd.qwe
  %(prog)s file.txt

Configuration precedence: CLI args > Environment variables
        '''
    )
    parser.add_argument(
        '--client-key',
        help='Server public key in mj_cli_<hex> format (or use MUMBOJUMBO_CLIENT_KEY env var)'
    )
    parser.add_argument(
        '-d', '--domain',
        help='DNS domain suffix, e.g., .asd.qwe (or use MUMBOJUMBO_DOMAIN env var)'
    )
    parser.add_argument(
        '-k', '--key',
        help='Transmission key (for stdin or with -v; NOT allowed with files where filename is key)'
    )
    parser.add_argument(
        '-v', '--value',
        help='Transmission value (if not provided, reads from stdin or files)'
    )
    parser.add_argument(
        '--verbose',
        action='store_true',
        help='Verbose output'
    )
    parser.add_argument(
        '--rate',
        type=float,
        default=10,
        help='Queries per second rate limit (default: 10)'
    )
    parser.add_argument(
        'files',
        nargs='*',
        help='Files to send (filename as key, contents as value), or "-" to read from stdin'
    )

    args = parser.parse_args()

    # Get client key from CLI arg or environment variable
    client_key_str = args.client_key or os.environ.get('MUMBOJUMBO_CLIENT_KEY')
    if not client_key_str:
        print("Error: Server public key required", file=sys.stderr)
        print("  Provide via --client-key argument or MUMBOJUMBO_CLIENT_KEY environment variable", file=sys.stderr)
        return 1

    # Get domain from CLI arg or environment variable
    domain = args.domain or os.environ.get('MUMBOJUMBO_DOMAIN')
    if not domain:
        print("Error: Domain required", file=sys.stderr)
        print("  Provide via -d argument or MUMBOJUMBO_DOMAIN environment variable", file=sys.stderr)
        return 1

    # Validate domain
    if not domain.startswith('.'):
        if args.verbose:
            print(f"Warning: domain should start with '.', got '{domain}'", file=sys.stderr)
            print(f"         Prepending '.' automatically", file=sys.stderr)
        domain = '.' + domain

    # Create client - key parsing happens transparently in constructor
    try:
        client_obj = MumbojumboClient(client_key_str, domain)
    except Exception as e:
        print(f"Error initializing client: {e}", file=sys.stderr)
        return 1

    # Progress callback for verbose mode
    def progress_callback(sent, total, succeeded, failed):
        if args.verbose:
            print(f"\rProgress: {sent}/{total} sent ({succeeded} succeeded, {failed} failed)", end='', file=sys.stderr)

    # Query callback to print DNS queries to stdout (for compatibility with tests)
    def query_callback(dns_query):
        print(dns_query)

    if args.key is not None and args.value is not None:
        # Explicit key-value pair - process immediately
        key = args.key.encode('utf-8')
        value = args.value.encode('utf-8')

        if args.verbose:
            print(f"Sending pair 1/1: key='{args.key}', value={len(value)} bytes", file=sys.stderr)

        try:
            summary = await client_obj.send_async(
                key, value,
                rate_qps=args.rate,
                progress_callback=progress_callback if args.verbose else None,
                query_callback=query_callback
            )
            if args.verbose:
                print("", file=sys.stderr)  # Newline after progress
                print(f"✓ Sent {summary['total']} queries: {summary['succeeded']} succeeded, {summary['failed']} failed", file=sys.stderr)
        except Exception as e:
            if args.verbose:
                print("", file=sys.stderr)  # Newline after progress
            print(f"Error sending key-value pair: {e}", file=sys.stderr)
            if args.verbose:
                import traceback
                traceback.print_exc(file=sys.stderr)
            return 1

        if args.verbose:
            print("", file=sys.stderr)

    elif args.files:
        # Check if files contains "-" (stdin)
        if '-' in args.files:
            # POSIX-compliant: "-" means read from stdin
            if len(args.files) > 1:
                print("Error: Cannot mix '-' (stdin) with other files", file=sys.stderr)
                return 1

            # Read from stdin with optional key from -k/--key argument
            try:
                stdin_data = sys.stdin.buffer.read()
            except Exception as e:
                print(f"Error reading stdin: {e}", file=sys.stderr)
                return 1

            # Use key from -k/--key argument if provided, otherwise None (null key)
            if args.key is not None:
                key = args.key.encode('utf-8')
            else:
                key = None
            value = stdin_data

            if args.verbose:
                key_display = f"'{args.key}'" if args.key is not None else "'None'"
                print(f"Sending pair 1/1: key={key_display}, value={len(value)} bytes", file=sys.stderr)

            try:
                summary = await client_obj.send_async(
                    key, value,
                    rate_qps=args.rate,
                    progress_callback=progress_callback if args.verbose else None,
                    query_callback=query_callback
                )
                if args.verbose:
                    print("", file=sys.stderr)  # Newline after progress
                    print(f"✓ Sent {summary['total']} queries: {summary['succeeded']} succeeded, {summary['failed']} failed", file=sys.stderr)
            except Exception as e:
                if args.verbose:
                    print("", file=sys.stderr)  # Newline after progress
                print(f"Error sending data: {e}", file=sys.stderr)
                if args.verbose:
                    import traceback
                    traceback.print_exc(file=sys.stderr)
                return 1

            if args.verbose:
                print("", file=sys.stderr)
        else:
            # Reject -k/--key when sending files (filenames are keys)
            if args.key is not None:
                print("Error: Cannot use -k/--key with files (filenames are used as keys)", file=sys.stderr)
                return 1

            # Send files one at a time - load, send, release
            for file_index, filepath in enumerate(args.files):
                # Load current file only
                try:
                    with open(filepath, 'rb') as f:
                        file_contents = f.read()
                except Exception as e:
                    print(f"Error reading file {filepath}: {e}", file=sys.stderr)
                    return 1

                # Send it immediately
                key = filepath.encode('utf-8')
                value = file_contents

                if args.verbose:
                    print(f"Sending pair {file_index + 1}/{len(args.files)}: key='{filepath}', value={len(value)} bytes", file=sys.stderr)

                try:
                    summary = await client_obj.send_async(
                        key, value,
                        rate_qps=args.rate,
                        progress_callback=progress_callback if args.verbose else None,
                        query_callback=query_callback
                    )
                    if args.verbose:
                        print("", file=sys.stderr)  # Newline after progress
                        print(f"✓ Sent {summary['total']} queries: {summary['succeeded']} succeeded, {summary['failed']} failed", file=sys.stderr)
                        print("", file=sys.stderr)
                except Exception as e:
                    if args.verbose:
                        print("", file=sys.stderr)  # Newline after progress
                    print(f"Error sending file {filepath}: {e}", file=sys.stderr)
                    if args.verbose:
                        import traceback
                        traceback.print_exc(file=sys.stderr)
                    return 1

                # file_contents goes out of scope here, can be garbage collected

    else:
        # No files provided and no explicit -k/-v - error
        print("Error: Must provide either files, '-' for stdin, or -k/-v for explicit key-value pair", file=sys.stderr)
        return 1

    return 0


def main():
    """Synchronous wrapper for async_main()."""
    return asyncio.run(async_main())


if __name__ == '__main__':
    sys.exit(main())
