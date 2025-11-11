#!/usr/bin/env python3
"""Tests for key encoding/decoding with mj_priv_ and mj_pub_ prefixes."""

import pytest
import nacl.public
from mumbojumbo import encode_key_hex, decode_key_hex, get_nacl_keypair_hex


class TestKeyEncoding:
    """Test key encoding/decoding with mj_priv_ and mj_pub_ prefixes."""

    def test_encode_public_key(self):
        """Test encoding public key with mj_pub_ prefix."""
        private_key = nacl.public.PrivateKey.generate()
        pub_key_bytes = private_key.public_key.encode()

        encoded = encode_key_hex(pub_key_bytes, key_type='pub')

        # Check prefix
        assert encoded.startswith('mj_pub_')

        # Check length (mj_pub_ = 7 chars + 64 hex chars = 71 total)
        assert len(encoded) == 71

        # Check hex encoding
        hex_part = encoded[7:]
        assert pub_key_bytes.hex() == hex_part

    def test_encode_private_key(self):
        """Test encoding private key with mj_priv_ prefix."""
        private_key = nacl.public.PrivateKey.generate()
        priv_key_bytes = private_key.encode()

        encoded = encode_key_hex(priv_key_bytes, key_type='priv')

        # Check prefix
        assert encoded.startswith('mj_priv_')

        # Check length (mj_priv_ = 8 chars + 64 hex chars = 72 total)
        assert len(encoded) == 72

        # Check hex encoding
        hex_part = encoded[8:]
        assert priv_key_bytes.hex() == hex_part

    def test_encode_invalid_key_type(self):
        """Test that invalid key_type raises ValueError."""
        private_key = nacl.public.PrivateKey.generate()
        key_bytes = private_key.encode()

        with pytest.raises(ValueError, match='must be "priv" or "pub"'):
            encode_key_hex(key_bytes, key_type='invalid')

    def test_decode_public_key(self):
        """Test decoding public key with mj_pub_ prefix."""
        private_key = nacl.public.PrivateKey.generate()
        pub_key_bytes = private_key.public_key.encode()

        encoded = encode_key_hex(pub_key_bytes, key_type='pub')
        decoded = decode_key_hex(encoded)

        assert pub_key_bytes == decoded

    def test_decode_private_key(self):
        """Test decoding private key with mj_priv_ prefix."""
        private_key = nacl.public.PrivateKey.generate()
        priv_key_bytes = private_key.encode()

        encoded = encode_key_hex(priv_key_bytes, key_type='priv')
        decoded = decode_key_hex(encoded)

        assert priv_key_bytes == decoded

    def test_decode_invalid_prefix(self):
        """Test that keys without proper prefix raise ValueError."""
        # Test completely invalid prefix
        with pytest.raises(ValueError, match='must start with "mj_priv_" or "mj_pub_"'):
            decode_key_hex('invalid_prefix_1234567890abcdef')

        # Test legacy mj_ prefix (no longer supported)
        with pytest.raises(ValueError, match='must start with "mj_priv_" or "mj_pub_"'):
            decode_key_hex('mj_1234567890abcdef')

    def test_decode_invalid_hex(self):
        """Test that invalid hex raises ValueError."""
        with pytest.raises(ValueError, match='Invalid hex key format'):
            decode_key_hex('mj_pub_GGGGGG')  # G is not valid hex

    def test_get_nacl_keypair_hex(self):
        """Test keypair generation with new prefixes."""
        priv_str, pub_str = get_nacl_keypair_hex()

        # Check prefixes
        assert priv_str.startswith('mj_priv_')
        assert pub_str.startswith('mj_pub_')

        # Check lengths
        assert len(priv_str) == 72
        assert len(pub_str) == 71

        # Decode and verify they form a valid keypair
        priv_bytes = decode_key_hex(priv_str)
        pub_bytes = decode_key_hex(pub_str)

        # Reconstruct keypair and verify public key matches
        private_key = nacl.public.PrivateKey(priv_bytes)
        assert private_key.public_key.encode() == pub_bytes

    def test_round_trip_encoding(self):
        """Test encode->decode round trip for both key types."""
        private_key = nacl.public.PrivateKey.generate()

        # Test private key round trip
        priv_bytes = private_key.encode()
        priv_encoded = encode_key_hex(priv_bytes, key_type='priv')
        priv_decoded = decode_key_hex(priv_encoded)
        assert priv_bytes == priv_decoded

        # Test public key round trip
        pub_bytes = private_key.public_key.encode()
        pub_encoded = encode_key_hex(pub_bytes, key_type='pub')
        pub_decoded = decode_key_hex(pub_encoded)
        assert pub_bytes == pub_decoded
