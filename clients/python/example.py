#!/usr/bin/env python3
"""
Minimal example showing how to use MumbojumboClient as a library.

This demonstrates the clean, user-friendly async interface with rate control.
"""

import asyncio
from mumbojumbo_client import MumbojumboClient


async def async_example():
    """Example using async API (recommended)."""
    # 1. Initialize client with server's public key and domain
    client = MumbojumboClient(
        server_client_key='mj_cli_0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef',
        domain='.example.com'
    )

    # 2. Send key-value pairs with rate limiting (fire-and-forget)
    print("Sending with async API (recommended)...")

    def progress(sent, total, succeeded, failed):
        """Progress callback for real-time updates."""
        print(f"  Progress: {sent}/{total} sent ({succeeded} succeeded, {failed} failed)")

    summary = await client.send_async(
        key=b'filename.txt',
        value=b'Hello, World!',
        rate_qps=10,          # 10 queries per second
        progress_callback=progress
    )
    print(f"✓ Complete! {summary['succeeded']}/{summary['total']} queries succeeded")


def sync_example():
    """Example using synchronous API (convenience wrapper)."""
    # 1. Initialize client
    client = MumbojumboClient(
        server_client_key='mj_cli_0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef',
        domain='.example.com'
    )

    # 2. Send with synchronous wrapper (blocks until all queries sent)
    print("\nSending with sync API (convenience wrapper)...")
    client.send_sync(
        key=b'mykey',
        value=b'myvalue',
        rate_qps=20
    )
    print("✓ All queries sent!")


def generate_queries_example():
    """Example generating queries without sending."""
    client = MumbojumboClient(
        server_client_key='mj_cli_0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef',
        domain='.example.com'
    )

    # Generate queries without sending
    print("\nGenerating queries without sending...")
    queries = client.generate_queries(b'testkey', b'testvalue')
    print(f"Generated {len(queries)} DNS queries:")
    for i, query in enumerate(queries, 1):
        print(f"  {i}. {query[:80]}...")  # Show first 80 chars


def main():
    """Run all examples."""
    # Run async example
    asyncio.run(async_example())

    # Run sync example
    sync_example()

    # Run query generation example
    generate_queries_example()


if __name__ == '__main__':
    main()
