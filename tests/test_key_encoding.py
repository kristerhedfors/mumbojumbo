#!/usr/bin/env python3
"""Tests for key encoding/decoding with mj_srv_ and mj_cli_ prefixes."""

import pytest
import nacl.public
from mumbojumbo import encode_key_hex, decode_key_hex, get_nacl_keypair_hex


class TestKeyEncoding:
    """Test key encoding/decoding with mj_srv_ and mj_cli_ prefixes."""

    def test_encode_client_key(self):
        """Test encoding client key with mj_cli_ prefix."""
        private_key = nacl.public.PrivateKey.generate()
        cli_key_bytes = private_key.public_key.encode()

        encoded = encode_key_hex(cli_key_bytes, key_type='cli')

        # Check prefix
        assert encoded.startswith('mj_cli_')

        # Check length (mj_cli_ = 7 chars + 64 hex chars = 71 total)
        assert len(encoded) == 71

        # Check hex encoding
        hex_part = encoded[7:]
        assert cli_key_bytes.hex() == hex_part

    def test_encode_server_key(self):
        """Test encoding server key with mj_srv_ prefix."""
        private_key = nacl.public.PrivateKey.generate()
        srv_key_bytes = private_key.encode()

        encoded = encode_key_hex(srv_key_bytes, key_type='srv')

        # Check prefix
        assert encoded.startswith('mj_srv_')

        # Check length (mj_srv_ = 7 chars + 64 hex chars = 71 total)
        assert len(encoded) == 71

        # Check hex encoding
        hex_part = encoded[7:]
        assert srv_key_bytes.hex() == hex_part

    def test_encode_invalid_key_type(self):
        """Test that invalid key_type raises ValueError."""
        private_key = nacl.public.PrivateKey.generate()
        key_bytes = private_key.encode()

        with pytest.raises(ValueError, match='must be "srv" or "cli"'):
            encode_key_hex(key_bytes, key_type='invalid')

    def test_decode_client_key(self):
        """Test decoding client key with mj_cli_ prefix."""
        private_key = nacl.public.PrivateKey.generate()
        cli_key_bytes = private_key.public_key.encode()

        encoded = encode_key_hex(cli_key_bytes, key_type='cli')
        decoded = decode_key_hex(encoded)

        assert cli_key_bytes == decoded

    def test_decode_server_key(self):
        """Test decoding server key with mj_srv_ prefix."""
        private_key = nacl.public.PrivateKey.generate()
        srv_key_bytes = private_key.encode()

        encoded = encode_key_hex(srv_key_bytes, key_type='srv')
        decoded = decode_key_hex(encoded)

        assert srv_key_bytes == decoded

    def test_decode_invalid_prefix(self):
        """Test that keys without proper prefix raise ValueError."""
        # Test completely invalid prefix
        with pytest.raises(ValueError, match='must start with "mj_srv_" or "mj_cli_"'):
            decode_key_hex('invalid_prefix_1234567890abcdef')

        # Test legacy mj_ prefix (no longer supported)
        with pytest.raises(ValueError, match='must start with "mj_srv_" or "mj_cli_"'):
            decode_key_hex('mj_1234567890abcdef')

    def test_decode_invalid_hex(self):
        """Test that invalid hex raises ValueError."""
        with pytest.raises(ValueError, match='Invalid hex key format'):
            decode_key_hex('mj_cli_GGGGGG')  # G is not valid hex

    def test_get_nacl_keypair_hex(self):
        """Test keypair generation with new prefixes."""
        srv_str, cli_str = get_nacl_keypair_hex()

        # Check prefixes
        assert srv_str.startswith('mj_srv_')
        assert cli_str.startswith('mj_cli_')

        # Check lengths
        assert len(srv_str) == 71
        assert len(cli_str) == 71

        # Decode and verify they form a valid keypair
        srv_bytes = decode_key_hex(srv_str)
        cli_bytes = decode_key_hex(cli_str)

        # Reconstruct keypair and verify public key matches
        private_key = nacl.public.PrivateKey(srv_bytes)
        assert private_key.public_key.encode() == cli_bytes

    def test_round_trip_encoding(self):
        """Test encode->decode round trip for both key types."""
        private_key = nacl.public.PrivateKey.generate()

        # Test server key round trip
        srv_bytes = private_key.encode()
        srv_encoded = encode_key_hex(srv_bytes, key_type='srv')
        srv_decoded = decode_key_hex(srv_encoded)
        assert srv_bytes == srv_decoded

        # Test client key round trip
        cli_bytes = private_key.public_key.encode()
        cli_encoded = encode_key_hex(cli_bytes, key_type='cli')
        cli_decoded = decode_key_hex(cli_encoded)
        assert cli_bytes == cli_decoded
