#!/usr/bin/env python3
"""Tests for Python mumbojumbo client v2.0.

Tests the MumbojumboClient class and its integration with the server.
"""

import os
import sys
import secrets

import pytest

# Import client module dynamically
client_path = os.path.join(os.path.dirname(__file__), '..', 'clients', 'python', 'mumbojumbo_client.py')
import importlib.util
spec = importlib.util.spec_from_file_location("mumbojumbo_client", client_path)
client = importlib.util.module_from_spec(spec)
spec.loader.exec_module(client)

# Import server components for integration tests
from mumbojumbo import (
    PacketEngine,
    DnsFragment,
    derive_keys,
    encode_key_hex,
    decode_mumbojumbo_key,
)


class TestKeyDecoding:
    """Test client key decoding."""

    def test_decode_valid_hex_key(self):
        """Valid mj_cli_ hex key should decode correctly."""
        key_bytes = secrets.token_bytes(32)
        key_str = 'mj_cli_' + key_bytes.hex()

        decoded = client.decode_mumbojumbo_key(key_str)
        assert decoded == key_bytes

    def test_decode_raw_hex(self):
        """Raw hex without prefix should decode."""
        key_bytes = secrets.token_bytes(32)
        decoded = client.decode_mumbojumbo_key(key_bytes.hex())
        assert decoded == key_bytes

    def test_decode_invalid_hex_raises(self):
        """Invalid hex characters should raise ValueError."""
        with pytest.raises(ValueError, match='Invalid mumbojumbo key'):
            client.decode_mumbojumbo_key('mj_cli_' + 'ZZZZ' * 16)

    def test_decode_wrong_length_raises(self):
        """Wrong key length should raise ValueError."""
        with pytest.raises(ValueError, match='Key must be 32 bytes'):
            client.decode_mumbojumbo_key('mj_cli_' + 'aa' * 10)


class TestClientKeyDerivation:
    """Test that client derives same keys as server."""

    def test_derive_keys_matches_server(self):
        """Client key derivation should match server implementation."""
        client_key = secrets.token_bytes(32)

        # Server derivation
        server_enc, server_auth, server_frag = derive_keys(client_key)

        # Client derivation
        client_enc, client_auth, client_frag = client.derive_keys(client_key)

        assert client_enc == server_enc
        assert client_auth == server_auth
        assert client_frag == server_frag

    def test_derivation_is_deterministic(self):
        """Same client key should always derive same keys."""
        key = secrets.token_bytes(32)

        enc1, auth1, frag1 = client.derive_keys(key)
        enc2, auth2, frag2 = client.derive_keys(key)

        assert enc1 == enc2
        assert auth1 == auth2
        assert frag1 == frag2


class TestMumbojumboClientInit:
    """Test MumbojumboClient initialization."""

    def test_init_with_hex_string(self, client_key_hex):
        """Client should accept hex string key."""
        mc = client.MumbojumboClient(client_key_hex, '.test.com')
        assert mc.domain == '.test.com'
        assert mc.enc_key is not None
        assert mc.auth_key is not None
        assert mc.frag_key is not None

    def test_init_with_bytes(self, client_key_bytes):
        """Client should accept raw bytes key."""
        mc = client.MumbojumboClient(client_key_bytes, '.test.com')
        assert mc.domain == '.test.com'

    def test_init_derives_keys(self, client_key_bytes):
        """Client should derive enc/auth/frag keys on init."""
        mc = client.MumbojumboClient(client_key_bytes, '.test.com')

        expected_enc, expected_auth, expected_frag = derive_keys(client_key_bytes)

        assert mc.enc_key == expected_enc
        assert mc.auth_key == expected_auth
        assert mc.frag_key == expected_frag

    def test_packet_id_initialized_randomly(self):
        """Packet ID should be randomly initialized."""
        key = secrets.token_bytes(32)
        clients = [client.MumbojumboClient(key, '.test.com') for _ in range(10)]
        ids = [c._next_packet_id for c in clients]

        # Should have some diversity
        assert len(set(ids)) > 5

    def test_default_resolver(self, client_key_bytes):
        """Default resolver should be 8.8.8.8."""
        mc = client.MumbojumboClient(client_key_bytes, '.test.com')
        assert mc.resolver == '8.8.8.8'

    def test_custom_resolver(self, client_key_bytes):
        """Custom resolver should be accepted."""
        mc = client.MumbojumboClient(client_key_bytes, '.test.com', resolver='1.1.1.1')
        assert mc.resolver == '1.1.1.1'


class TestClientGenerateQueries:
    """Test MumbojumboClient.generate_queries()."""

    def test_returns_list_of_strings(self, client_key_bytes):
        """generate_queries should return list of DNS query strings."""
        mc = client.MumbojumboClient(client_key_bytes, '.test.com')
        queries = mc.generate_queries(key=b'mykey', value=b'myvalue')

        assert isinstance(queries, list)
        assert len(queries) > 0
        for q in queries:
            assert isinstance(q, str)
            assert q.endswith('.test.com')

    def test_query_format_63_char_label(self, client_key_bytes):
        """Query should have 63-character base36 label."""
        mc = client.MumbojumboClient(client_key_bytes, '.test.com')
        queries = mc.generate_queries(key=b'k', value=b'v')

        for query in queries:
            label = query[:-len('.test.com')]
            assert len(label) == 63  # Padded base36

    def test_small_message_single_query(self, client_key_bytes):
        """Small message should produce single query."""
        mc = client.MumbojumboClient(client_key_bytes, '.test.com')
        queries = mc.generate_queries(key=b'', value=b'tiny')

        # Small message fits in one fragment
        assert len(queries) == 1

    def test_large_message_multiple_queries(self, client_key_bytes):
        """Large message should produce multiple queries."""
        mc = client.MumbojumboClient(client_key_bytes, '.test.com')
        queries = mc.generate_queries(key=b'big', value=b'X' * 200)

        # Should need multiple fragments
        assert len(queries) > 1

    def test_none_key_allowed(self, client_key_bytes):
        """None key should be treated as empty."""
        mc = client.MumbojumboClient(client_key_bytes, '.test.com')
        queries = mc.generate_queries(key=None, value=b'data')
        assert len(queries) > 0

    def test_none_value_raises(self, client_key_bytes):
        """None value should raise ValueError."""
        mc = client.MumbojumboClient(client_key_bytes, '.test.com')
        with pytest.raises(ValueError, match='Value cannot be None'):
            mc.generate_queries(key=b'k', value=None)

    def test_key_too_long_raises(self, client_key_bytes):
        """Key > 255 bytes should raise ValueError."""
        mc = client.MumbojumboClient(client_key_bytes, '.test.com')
        with pytest.raises(ValueError, match='Key too long'):
            mc.generate_queries(key=b'X' * 256, value=b'v')

    def test_increments_packet_id(self, client_key_bytes):
        """Each call should increment packet ID."""
        mc = client.MumbojumboClient(client_key_bytes, '.test.com')
        initial_id = mc._next_packet_id

        mc.generate_queries(key=b'', value=b'first')
        assert mc._next_packet_id == (initial_id + 1) & 0xFFFFFFFF

        mc.generate_queries(key=b'', value=b'second')
        assert mc._next_packet_id == (initial_id + 2) & 0xFFFFFFFF


class TestClientServerIntegration:
    """Test that client-generated queries can be decoded by server."""

    def test_single_fragment_round_trip(self, client_key_bytes):
        """Single fragment from client should be decoded by server."""
        # Client
        mc = client.MumbojumboClient(client_key_bytes, '.test.com')
        queries = mc.generate_queries(key=b'mykey', value=b'myvalue')

        # Server
        enc_key, auth_key, frag_key = derive_keys(client_key_bytes)
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

        # Feed client queries to server
        for query in queries:
            engine.from_wire(query)

        # Verify server decoded correctly
        packet = engine.packet_outqueue.get()
        assert packet['key'] == b'mykey'
        assert packet['value'] == b'myvalue'

    def test_multi_fragment_round_trip(self, client_key_bytes):
        """Multi-fragment message should be decoded by server."""
        # Client
        mc = client.MumbojumboClient(client_key_bytes, '.test.com')
        key = b'document.pdf'
        value = secrets.token_bytes(200)
        queries = mc.generate_queries(key=key, value=value)
        assert len(queries) > 1

        # Server
        enc_key, auth_key, frag_key = derive_keys(client_key_bytes)
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

        for query in queries:
            engine.from_wire(query)

        packet = engine.packet_outqueue.get()
        assert packet['key'] == key
        assert packet['value'] == value

    def test_empty_key_round_trip(self, client_key_bytes):
        """Empty key should work end-to-end."""
        # Client
        mc = client.MumbojumboClient(client_key_bytes, '.test.com')
        queries = mc.generate_queries(key=b'', value=b'data without key')

        # Server
        enc_key, auth_key, frag_key = derive_keys(client_key_bytes)
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

        for query in queries:
            engine.from_wire(query)

        packet = engine.packet_outqueue.get()
        assert packet['key'] == b''
        assert packet['value'] == b'data without key'
        assert packet['key_length'] == 0

    def test_max_key_length_round_trip(self, client_key_bytes):
        """Max key length (255 bytes) should work end-to-end."""
        # Client
        mc = client.MumbojumboClient(client_key_bytes, '.test.com')
        key = b'K' * 255
        value = b'value'
        queries = mc.generate_queries(key=key, value=value)

        # Server
        enc_key, auth_key, frag_key = derive_keys(client_key_bytes)
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

        for query in queries:
            engine.from_wire(query)

        packet = engine.packet_outqueue.get()
        assert packet['key'] == key
        assert packet['value'] == value
        assert packet['key_length'] == 255

    def test_binary_data_round_trip(self, client_key_bytes):
        """Binary data with null bytes should work."""
        # Client
        mc = client.MumbojumboClient(client_key_bytes, '.test.com')
        key = b'\x00\x01\x02'
        value = b'\xff\xfe\xfd\x00\x00\x01'
        queries = mc.generate_queries(key=key, value=value)

        # Server
        enc_key, auth_key, frag_key = derive_keys(client_key_bytes)
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

        for query in queries:
            engine.from_wire(query)

        packet = engine.packet_outqueue.get()
        assert packet['key'] == key
        assert packet['value'] == value

    def test_multiple_messages_from_same_client(self, client_key_bytes):
        """Multiple messages from same client should work."""
        mc = client.MumbojumboClient(client_key_bytes, '.test.com')

        # Server
        enc_key, auth_key, frag_key = derive_keys(client_key_bytes)
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

        # Send multiple messages
        messages = [
            (b'key1', b'value1'),
            (b'key2', b'value2' * 50),  # Larger value
            (b'', b'no key message'),
        ]

        for key, value in messages:
            queries = mc.generate_queries(key=key, value=value)
            for query in queries:
                engine.from_wire(query)

        # Verify all received
        for key, value in messages:
            packet = engine.packet_outqueue.get()
            assert packet['key'] == key
            assert packet['value'] == value


class TestClientFragmentCreation:
    """Test internal fragment creation methods."""

    def test_create_fragment_40_bytes(self, client_key_bytes):
        """_create_fragment should produce 40-byte packet."""
        mc = client.MumbojumboClient(client_key_bytes, '.test.com')
        packet = mc._create_fragment(
            packet_id=0x12345678,
            frag_index=0,
            is_first=True,
            has_more=False,
            frag_data=b'test'
        )
        assert len(packet) == 40

    def test_create_dns_query_format(self, client_key_bytes):
        """_create_dns_query should produce proper DNS query."""
        mc = client.MumbojumboClient(client_key_bytes, '.test.com')
        packet = mc._create_fragment(1, 0, True, False, b'x')
        dns_query = mc._create_dns_query(packet)

        assert dns_query.endswith('.test.com')
        label = dns_query[:-len('.test.com')]
        assert len(label) == 63

    def test_encrypt_message_structure(self, client_key_bytes):
        """_encrypt_message should produce nonce + integrity + ciphertext."""
        mc = client.MumbojumboClient(client_key_bytes, '.test.com')
        plaintext = b'test message'
        encrypted = mc._encrypt_message(plaintext)

        # 8 nonce + 8 integrity + len(plaintext)
        assert len(encrypted) == 8 + 8 + len(plaintext)


class TestClientCryptoCompatibility:
    """Test that client crypto matches server crypto."""

    def test_chacha20_compatibility(self):
        """Client and server ChaCha20 should be identical."""
        from mumbojumbo import chacha20_encrypt as server_chacha

        key = secrets.token_bytes(32)
        nonce = secrets.token_bytes(8)
        plaintext = b'test data'

        client_cipher = client.chacha20_encrypt(key, nonce, plaintext)
        server_cipher = server_chacha(key, nonce, plaintext)

        assert client_cipher == server_cipher

    def test_poly1305_compatibility(self):
        """Client and server Poly1305 should be identical."""
        from mumbojumbo import poly1305_mac as server_poly

        key = secrets.token_bytes(32)
        msg = b'test message'

        client_mac = client.poly1305_mac(key, msg)
        server_mac = server_poly(key, msg)

        assert client_mac == server_mac

    def test_base36_encode_compatibility(self):
        """Client and server base36 encoding should be identical."""
        from mumbojumbo import base36_encode as server_b36

        data = secrets.token_bytes(40)

        client_encoded = client.base36_encode(data)
        server_encoded = server_b36(data)

        assert client_encoded == server_encoded


class TestClientEdgeCases:
    """Test edge cases and boundary conditions for client."""

    def test_very_long_domain(self, client_key_bytes):
        """Very long domain should work."""
        domain = '.very.long.subdomain.example.com'
        mc = client.MumbojumboClient(client_key_bytes, domain)
        queries = mc.generate_queries(key=b'k', value=b'v')

        for q in queries:
            assert q.endswith(domain)

    def test_single_byte_value(self, client_key_bytes):
        """Single byte value should work."""
        mc = client.MumbojumboClient(client_key_bytes, '.test.com')
        queries = mc.generate_queries(key=b'', value=b'X')
        assert len(queries) > 0

    def test_large_value(self, client_key_bytes):
        """Large value (1KB) should work."""
        mc = client.MumbojumboClient(client_key_bytes, '.test.com')
        value = secrets.token_bytes(1024)
        queries = mc.generate_queries(key=b'big', value=value)
        assert len(queries) > 10  # Should need many fragments

    def test_packet_id_wraparound(self, client_key_bytes):
        """Packet ID should wrap at u32 max."""
        mc = client.MumbojumboClient(client_key_bytes, '.test.com')
        mc._next_packet_id = 0xFFFFFFFF

        mc.generate_queries(key=b'', value=b'wrap')

        assert mc._next_packet_id == 0
