#!/usr/bin/env python3
"""Integration tests for mumbojumbo v2.0 protocol.

End-to-end tests verifying complete client-server communication.
"""

import os
import secrets
import subprocess
import sys

import pytest

# Import server components
from mumbojumbo import (
    PacketEngine,
    DnsFragment,
    derive_keys,
    get_client_key_hex,
    decode_mumbojumbo_key,
    validate_domain,
)

# Import client module
client_path = os.path.join(os.path.dirname(__file__), '..', 'clients', 'python', 'mumbojumbo_client.py')
import importlib.util
spec = importlib.util.spec_from_file_location("mumbojumbo_client", client_path)
client = importlib.util.module_from_spec(spec)
spec.loader.exec_module(client)


class TestFullProtocolFlow:
    """Test complete protocol flow from key generation to message delivery."""

    def test_key_generation_to_message_delivery(self):
        """Full flow: generate key → client sends → server receives."""
        # Step 1: Generate client key (server would do this)
        client_key_hex = get_client_key_hex()
        assert client_key_hex.startswith('mj_cli_')

        # Step 2: Client uses key to send message
        mc = client.MumbojumboClient(client_key_hex, '.example.com')
        queries = mc.generate_queries(key=b'secret.txt', value=b'Top secret data!')

        # Step 3: Server uses same key to receive
        client_key_bytes = decode_mumbojumbo_key(client_key_hex)
        enc_key, auth_key, frag_key = derive_keys(client_key_bytes)
        frag_cls = DnsFragment.bind(
            domain='.example.com',
            enc_key=enc_key,
            auth_key=auth_key,
            frag_key=frag_key
        )
        engine = PacketEngine(
            frag_cls=frag_cls,
            enc_key=enc_key,
            auth_key=auth_key,
            frag_key=frag_key
        )

        # Step 4: Process queries
        for query in queries:
            engine.from_wire(query)

        # Step 5: Verify message received
        packet = engine.packet_outqueue.get()
        assert packet['key'] == b'secret.txt'
        assert packet['value'] == b'Top secret data!'

    def test_multiple_clients_same_key(self):
        """Multiple client instances with same key should all work."""
        client_key = secrets.token_bytes(32)
        enc_key, auth_key, frag_key = derive_keys(client_key)

        # Create multiple client instances
        mc1 = client.MumbojumboClient(client_key, '.test.com')
        mc2 = client.MumbojumboClient(client_key, '.test.com')
        mc3 = client.MumbojumboClient(client_key, '.test.com')

        # Single server engine
        frag_cls = DnsFragment.bind(
            domain='.test.com',
            enc_key=enc_key,
            auth_key=auth_key,
            frag_key=frag_key
        )
        engine = PacketEngine(
            frag_cls=frag_cls,
            enc_key=enc_key,
            auth_key=auth_key,
            frag_key=frag_key
        )

        # Each client sends a message
        messages = [
            (mc1, b'client1', b'message from client 1'),
            (mc2, b'client2', b'message from client 2'),
            (mc3, b'client3', b'message from client 3'),
        ]

        for mc, key, value in messages:
            queries = mc.generate_queries(key=key, value=value)
            for query in queries:
                engine.from_wire(query)

        # All messages should be received
        received = []
        for _ in range(3):
            received.append(engine.packet_outqueue.get())

        keys_received = set(p['key'] for p in received)
        assert keys_received == {b'client1', b'client2', b'client3'}

    def test_different_domains_isolated(self):
        """Messages to different domains should not interfere."""
        client_key = secrets.token_bytes(32)
        enc_key, auth_key, frag_key = derive_keys(client_key)

        # Client sends to domain1
        mc1 = client.MumbojumboClient(client_key, '.domain1.com')
        queries1 = mc1.generate_queries(key=b'k1', value=b'v1')

        # Server listens on domain2 - should reject domain1 packets
        frag_cls2 = DnsFragment.bind(
            domain='.domain2.com',
            enc_key=enc_key,
            auth_key=auth_key,
            frag_key=frag_key
        )
        engine2 = PacketEngine(
            frag_cls=frag_cls2,
            enc_key=enc_key,
            auth_key=auth_key,
            frag_key=frag_key
        )

        for query in queries1:
            engine2.from_wire(query)

        # Should not have received anything (wrong domain)
        assert engine2.packet_outqueue.empty()


class TestSecurityProperties:
    """Test security properties of the protocol."""

    def test_wrong_key_fails_to_decrypt(self):
        """Using wrong key should fail to decrypt."""
        # Client uses key1
        client_key1 = secrets.token_bytes(32)
        mc = client.MumbojumboClient(client_key1, '.test.com')
        queries = mc.generate_queries(key=b'secret', value=b'data')

        # Server uses key2
        client_key2 = secrets.token_bytes(32)
        enc_key2, auth_key2, frag_key2 = derive_keys(client_key2)
        frag_cls = DnsFragment.bind(
            domain='.test.com',
            enc_key=enc_key2,
            auth_key=auth_key2,
            frag_key=frag_key2
        )
        engine = PacketEngine(
            frag_cls=frag_cls,
            enc_key=enc_key2,
            auth_key=auth_key2,
            frag_key=frag_key2
        )

        for query in queries:
            engine.from_wire(query)

        # Should fail (MAC verification will fail)
        assert engine.packet_outqueue.empty()

    def test_tampered_query_rejected(self):
        """Tampered DNS query should be rejected."""
        client_key = secrets.token_bytes(32)
        mc = client.MumbojumboClient(client_key, '.test.com')
        queries = mc.generate_queries(key=b'key', value=b'value')

        enc_key, auth_key, frag_key = derive_keys(client_key)
        frag_cls = DnsFragment.bind(
            domain='.test.com',
            enc_key=enc_key,
            auth_key=auth_key,
            frag_key=frag_key
        )
        engine = PacketEngine(
            frag_cls=frag_cls,
            enc_key=enc_key,
            auth_key=auth_key,
            frag_key=frag_key
        )

        # Tamper with query (change a character in base36 part)
        tampered = list(queries[0])
        # Change first character (avoiding changing to invalid char)
        tampered[0] = 'A' if tampered[0] != 'A' else 'B'
        tampered_query = ''.join(tampered)

        engine.from_wire(tampered_query)

        # Should be rejected
        assert engine.packet_outqueue.empty()

    def test_encryption_is_confidential(self):
        """Same plaintext should produce different ciphertext."""
        client_key = secrets.token_bytes(32)
        mc = client.MumbojumboClient(client_key, '.test.com')

        # Same message twice
        queries1 = mc.generate_queries(key=b'key', value=b'same message')
        queries2 = mc.generate_queries(key=b'key', value=b'same message')

        # Should be different (random nonces in encryption)
        assert queries1 != queries2

    def test_fragment_mac_prevents_corruption(self):
        """Fragment MAC should detect any corruption."""
        client_key = secrets.token_bytes(32)
        mc = client.MumbojumboClient(client_key, '.test.com')

        # Create large message with multiple fragments
        queries = mc.generate_queries(key=b'k', value=b'X' * 100)
        assert len(queries) > 1

        enc_key, auth_key, frag_key = derive_keys(client_key)
        frag_cls = DnsFragment.bind(
            domain='.test.com',
            enc_key=enc_key,
            auth_key=auth_key,
            frag_key=frag_key
        )
        engine = PacketEngine(
            frag_cls=frag_cls,
            enc_key=enc_key,
            auth_key=auth_key,
            frag_key=frag_key
        )

        # Send first fragment correctly
        engine.from_wire(queries[0])

        # Corrupt second fragment (will fail MAC)
        corrupted = list(queries[1])
        corrupted[10] = 'Z' if corrupted[10] != 'Z' else 'A'
        engine.from_wire(''.join(corrupted))

        # Send rest correctly
        for query in queries[2:]:
            engine.from_wire(query)

        # Should not reassemble (missing valid second fragment)
        assert engine.packet_outqueue.empty()


class TestResilience:
    """Test protocol resilience to various conditions."""

    def test_out_of_order_delivery(self):
        """Out-of-order fragment delivery should still work."""
        client_key = secrets.token_bytes(32)
        mc = client.MumbojumboClient(client_key, '.test.com')
        queries = mc.generate_queries(key=b'ooo', value=b'A' * 100)
        assert len(queries) > 3

        enc_key, auth_key, frag_key = derive_keys(client_key)
        frag_cls = DnsFragment.bind(
            domain='.test.com',
            enc_key=enc_key,
            auth_key=auth_key,
            frag_key=frag_key
        )
        engine = PacketEngine(
            frag_cls=frag_cls,
            enc_key=enc_key,
            auth_key=auth_key,
            frag_key=frag_key
        )

        # Deliver in reverse order
        for query in reversed(queries):
            engine.from_wire(query)

        packet = engine.packet_outqueue.get()
        assert packet['key'] == b'ooo'
        assert packet['value'] == b'A' * 100

    def test_interleaved_packet_delivery(self):
        """Interleaved fragments from different packets should work."""
        client_key = secrets.token_bytes(32)
        mc = client.MumbojumboClient(client_key, '.test.com')

        # Two large messages
        queries1 = mc.generate_queries(key=b'msg1', value=b'X' * 100)
        queries2 = mc.generate_queries(key=b'msg2', value=b'Y' * 100)

        enc_key, auth_key, frag_key = derive_keys(client_key)
        frag_cls = DnsFragment.bind(
            domain='.test.com',
            enc_key=enc_key,
            auth_key=auth_key,
            frag_key=frag_key
        )
        engine = PacketEngine(
            frag_cls=frag_cls,
            enc_key=enc_key,
            auth_key=auth_key,
            frag_key=frag_key
        )

        # Interleave: q1[0], q2[0], q1[1], q2[1], ...
        max_len = max(len(queries1), len(queries2))
        for i in range(max_len):
            if i < len(queries1):
                engine.from_wire(queries1[i])
            if i < len(queries2):
                engine.from_wire(queries2[i])

        # Both should be received
        p1 = engine.packet_outqueue.get()
        p2 = engine.packet_outqueue.get()

        keys = {p1['key'], p2['key']}
        assert keys == {b'msg1', b'msg2'}

    def test_duplicate_fragments_handled(self):
        """Duplicate fragments should be handled (last one wins)."""
        client_key = secrets.token_bytes(32)
        mc = client.MumbojumboClient(client_key, '.test.com')
        queries = mc.generate_queries(key=b'dup', value=b'Z' * 100)

        enc_key, auth_key, frag_key = derive_keys(client_key)
        frag_cls = DnsFragment.bind(
            domain='.test.com',
            enc_key=enc_key,
            auth_key=auth_key,
            frag_key=frag_key
        )
        engine = PacketEngine(
            frag_cls=frag_cls,
            enc_key=enc_key,
            auth_key=auth_key,
            frag_key=frag_key
        )

        # Send first fragment multiple times
        for _ in range(3):
            engine.from_wire(queries[0])

        # Send rest normally
        for query in queries[1:]:
            engine.from_wire(query)

        # Should still reassemble correctly
        packet = engine.packet_outqueue.get()
        assert packet['key'] == b'dup'
        assert packet['value'] == b'Z' * 100


class TestDomainValidation:
    """Test domain validation utility."""

    def test_valid_domains(self):
        """Valid domains should pass."""
        valid_cases = [
            '.example.com',
            '.test.org',
            '.a.b',
            '.very.long.subdomain.example.com',
        ]

        for domain in valid_cases:
            valid, msg = validate_domain(domain)
            assert valid is True, f"Domain {domain} should be valid: {msg}"

    def test_domain_must_start_with_dot(self):
        """Domain must start with dot."""
        valid, msg = validate_domain('example.com')
        assert valid is False
        assert 'dot' in msg.lower()

    def test_domain_too_short(self):
        """Very short domain should fail."""
        valid, msg = validate_domain('.a')
        assert valid is False

    def test_domain_too_long(self):
        """Very long domain should fail."""
        long_domain = '.' + 'x' * 254
        valid, msg = validate_domain(long_domain)
        assert valid is False


class TestCLIKeyGeneration:
    """Test --gen-keys CLI functionality."""

    def test_gen_keys_output_format(self):
        """--gen-keys should output proper environment variable format."""
        result = subprocess.run(
            [sys.executable, 'mumbojumbo.py', '--gen-keys'],
            capture_output=True,
            text=True,
            timeout=5
        )

        assert result.returncode == 0
        lines = result.stdout.strip().split('\n')

        # Should have comment line + 2 export lines
        assert len(lines) >= 2

        # Check for client key export
        client_key_line = [l for l in lines if 'MUMBOJUMBO_CLIENT_KEY' in l][0]
        assert 'export' in client_key_line
        assert 'mj_cli_' in client_key_line

    def test_gen_keys_produces_valid_key(self):
        """Generated key should be valid."""
        result = subprocess.run(
            [sys.executable, 'mumbojumbo.py', '--gen-keys'],
            capture_output=True,
            text=True,
            timeout=5
        )

        # Extract key from output
        for line in result.stdout.split('\n'):
            if 'MUMBOJUMBO_CLIENT_KEY=' in line:
                # export MUMBOJUMBO_CLIENT_KEY=mj_cli_...
                key_str = line.split('=')[1].strip()

                # Should be decodable
                key_bytes = decode_mumbojumbo_key(key_str)
                assert len(key_bytes) == 32

                # Should be able to derive keys
                enc, auth, frag = derive_keys(key_bytes)
                assert len(enc) == 32
                assert len(auth) == 32
                assert len(frag) == 32
                break
        else:
            pytest.fail("No CLIENT_KEY found in output")

    def test_gen_keys_with_custom_domain(self):
        """--gen-keys should respect --domain argument."""
        result = subprocess.run(
            [sys.executable, 'mumbojumbo.py', '--gen-keys', '-d', '.custom.domain'],
            capture_output=True,
            text=True,
            timeout=5
        )

        assert result.returncode == 0
        assert '.custom.domain' in result.stdout
