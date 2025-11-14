#!/usr/bin/env python3
"""
Minimal example showing how to use MumbojumboClient as a library.

This demonstrates the clean, user-friendly interface - just import and send.
"""

from mumbojumbo_client import MumbojumboClient


def main():
    # 1. Initialize client with server's public key and domain
    client = MumbojumboClient(
        server_client_key='mj_cli_0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef',
        domain='.example.com'
    )

    # 2. Send key-value pairs - that's it!
    results = client.send(b'filename.txt', b'Hello, World!')

    # 3. Check results
    for query, success in results:
        print(f"Query: {query}")
        print(f"Success: {success}")

    # Alternative: Generate queries without sending
    queries = client.generate_queries(b'mykey', b'myvalue')
    print(f"\nGenerated {len(queries)} DNS queries")
    for query in queries:
        print(f"  {query}")


if __name__ == '__main__':
    main()
