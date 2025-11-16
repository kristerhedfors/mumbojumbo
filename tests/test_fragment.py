#!/usr/bin/env python3
"""Tests for Fragment serialization/deserialization in mumbojumbo v2.0 protocol.

Tests the new 40-byte wire format with dual-layer encryption.
"""

import secrets
import struct

import pytest

from mumbojumbo import (
    Fragment,
    DnsFragment,
    EncryptedFragment,
    derive_keys,
    base36_encode,
    base36_decode,
    BINARY_PACKET_SIZE,
    BASE36_PACKET_SIZE,
    FRAGMENT_PAYLOAD_SIZE,
)


class TestFragmentSerialization:
    """Test Fragment serialization to 40-byte wire format."""

    def test_serialize_produces_40_bytes(self, enc_key, frag_key):
        """Serialized fragment should be 40 bytes."""
        frag = Fragment(
            packet_id=0x12345678,
            frag_index=0,
            is_first=True,
            has_more=False,
            frag_data=b'test',
            enc_key=enc_key,
            frag_key=frag_key
        )
        serialized = frag.serialize()
        assert len(serialized) == BINARY_PACKET_SIZE

    def test_packet_id_in_first_4_bytes(self, enc_key, frag_key):
        """Packet ID should be in first 4 bytes, big-endian."""
        packet_id = 0xDEADBEEF
        frag = Fragment(
            packet_id=packet_id,
            frag_index=0,
            is_first=True,
            has_more=False,
            frag_data=b'test',
            enc_key=enc_key,
            frag_key=frag_key
        )
        serialized = frag.serialize()

        # First 4 bytes are packet_id
        recovered_id = struct.unpack('!I', serialized[:4])[0]
        assert recovered_id == packet_id

    def test_mac_in_bytes_4_to_8(self, enc_key, frag_key):
        """Fragment MAC should be in bytes 4-8."""
        frag = Fragment(
            packet_id=0x12345678,
            frag_index=0,
            is_first=True,
            has_more=False,
            frag_data=b'test',
            enc_key=enc_key,
            frag_key=frag_key
        )
        serialized = frag.serialize()

        # Bytes 4-8 are MAC (should be non-zero)
        mac = serialized[4:8]
        assert len(mac) == 4
        assert mac != b'\x00\x00\x00\x00'

    def test_encrypted_portion_is_32_bytes(self, enc_key, frag_key):
        """Encrypted portion (bytes 8-40) should be 32 bytes."""
        frag = Fragment(
            packet_id=0x12345678,
            frag_index=0,
            is_first=True,
            has_more=False,
            frag_data=b'test',
            enc_key=enc_key,
            frag_key=frag_key
        )
        serialized = frag.serialize()

        encrypted = serialized[8:40]
        assert len(encrypted) == 32

    def test_payload_padded_to_28_bytes(self, enc_key, frag_key):
        """Fragment payload should be padded to 28 bytes."""
        frag = Fragment(
            packet_id=0x12345678,
            frag_index=0,
            is_first=True,
            has_more=False,
            frag_data=b'short',  # Only 5 bytes
            enc_key=enc_key,
            frag_key=frag_key
        )
        serialized = frag.serialize()
        assert len(serialized) == BINARY_PACKET_SIZE  # Still 40 bytes


class TestFragmentDeserialization:
    """Test Fragment deserialization from 40-byte wire format."""

    def test_deserialize_round_trip(self, enc_key, frag_key):
        """Test serialize/deserialize round trip."""
        original = Fragment(
            packet_id=0xABCD1234,
            frag_index=5,
            is_first=True,
            has_more=True,
            frag_data=b'test data here',
            enc_key=enc_key,
            frag_key=frag_key
        )

        serialized = original.serialize()
        deserialized = original.deserialize(serialized)

        assert deserialized._packet_id == 0xABCD1234
        assert deserialized._frag_index == 5
        assert deserialized._is_first is True
        assert deserialized._has_more is True
        # Non-last fragment: payload is padded to 28 bytes (not stripped)
        assert deserialized._frag_data == b'test data here' + b'\x00' * (FRAGMENT_PAYLOAD_SIZE - 14)

    def test_deserialize_extracts_flags_correctly(self, enc_key, frag_key):
        """Test that flags are correctly extracted."""
        # Test first=True, more=True
        frag = Fragment(
            packet_id=1,
            frag_index=10,
            is_first=True,
            has_more=True,
            frag_data=b'x',
            enc_key=enc_key,
            frag_key=frag_key
        )
        recovered = frag.deserialize(frag.serialize())
        assert recovered._is_first is True
        assert recovered._has_more is True

        # Test first=False, more=True
        frag = Fragment(
            packet_id=1,
            frag_index=10,
            is_first=False,
            has_more=True,
            frag_data=b'x',
            enc_key=enc_key,
            frag_key=frag_key
        )
        recovered = frag.deserialize(frag.serialize())
        assert recovered._is_first is False
        assert recovered._has_more is True

        # Test first=False, more=False
        frag = Fragment(
            packet_id=1,
            frag_index=10,
            is_first=False,
            has_more=False,
            frag_data=b'x',
            enc_key=enc_key,
            frag_key=frag_key
        )
        recovered = frag.deserialize(frag.serialize())
        assert recovered._is_first is False
        assert recovered._has_more is False

    def test_deserialize_handles_30_bit_index(self, enc_key, frag_key):
        """Test that 30-bit fragment index is handled correctly."""
        # Maximum 30-bit value
        max_index = 0x3FFFFFFF  # 2^30 - 1
        frag = Fragment(
            packet_id=1,
            frag_index=max_index,
            is_first=False,
            has_more=False,
            frag_data=b'x',
            enc_key=enc_key,
            frag_key=frag_key
        )
        recovered = frag.deserialize(frag.serialize())
        assert recovered._frag_index == max_index

    def test_deserialize_invalid_size_returns_none(self, enc_key, frag_key):
        """Invalid packet size should return None."""
        frag = Fragment(enc_key=enc_key, frag_key=frag_key)

        # Too short
        assert frag.deserialize(b'short') is None
        # Too long
        assert frag.deserialize(b'x' * 50) is None
        # Empty
        assert frag.deserialize(b'') is None

    def test_deserialize_bad_mac_returns_none(self, enc_key, frag_key):
        """Invalid MAC should return None."""
        frag = Fragment(
            packet_id=1,
            frag_index=0,
            is_first=True,
            has_more=False,
            frag_data=b'test',
            enc_key=enc_key,
            frag_key=frag_key
        )
        serialized = bytearray(frag.serialize())

        # Corrupt MAC (bytes 4-8)
        serialized[4] ^= 0xFF

        recovered = frag.deserialize(bytes(serialized))
        assert recovered is None

    def test_deserialize_strips_trailing_zeros_from_last_fragment(self, enc_key, frag_key):
        """Trailing zeros stripped only from last fragment (has_more=False)."""
        # Last fragment (has_more=False) - trailing zeros stripped
        frag = Fragment(
            packet_id=1,
            frag_index=0,
            is_first=True,
            has_more=False,  # LAST fragment
            frag_data=b'hello',  # Will be padded to 28 bytes
            enc_key=enc_key,
            frag_key=frag_key
        )
        recovered = frag.deserialize(frag.serialize())
        # Should strip trailing zeros from last fragment
        assert recovered._frag_data == b'hello'

    def test_deserialize_keeps_full_payload_for_non_last(self, enc_key, frag_key):
        """Non-last fragments keep full 28-byte payload."""
        # Non-last fragment (has_more=True) - keep full payload
        frag = Fragment(
            packet_id=1,
            frag_index=0,
            is_first=True,
            has_more=True,  # NOT last fragment
            frag_data=b'hello',  # Will be padded to 28 bytes
            enc_key=enc_key,
            frag_key=frag_key
        )
        recovered = frag.deserialize(frag.serialize())
        # Should keep full padded payload (28 bytes)
        assert recovered._frag_data == b'hello' + b'\x00' * 23
        assert len(recovered._frag_data) == FRAGMENT_PAYLOAD_SIZE


class TestFragmentWithoutEncryption:
    """Test Fragment without encryption keys (plaintext mode)."""

    def test_serialize_without_keys_no_encryption(self):
        """Without keys, fragment should serialize but not encrypt."""
        frag = Fragment(
            packet_id=0x12345678,
            frag_index=0,
            is_first=True,
            has_more=False,
            frag_data=b'test',
            enc_key=None,
            frag_key=None
        )
        serialized = frag.serialize()
        assert len(serialized) == BINARY_PACKET_SIZE

        # MAC should be zeros when no frag_key
        mac = serialized[4:8]
        assert mac == b'\x00\x00\x00\x00'

    def test_deserialize_without_keys_skips_mac_check(self):
        """Without frag_key, MAC verification should be skipped."""
        frag = Fragment(
            packet_id=0x12345678,
            frag_index=0,
            is_first=True,
            has_more=False,
            frag_data=b'test',
            enc_key=None,
            frag_key=None
        )
        recovered = frag.deserialize(frag.serialize())
        assert recovered._packet_id == 0x12345678
        # Last fragment (has_more=False): trailing zeros stripped
        assert recovered._frag_data == b'test'


class TestDnsFragment:
    """Test DNS-encoded fragment operations."""

    def test_serialize_to_dns_query(self, enc_key, auth_key, frag_key):
        """Test serialization to DNS query string."""
        frag = DnsFragment(
            domain='.test.com',
            packet_id=1,
            frag_index=0,
            is_first=True,
            has_more=False,
            frag_data=b'test',
            enc_key=enc_key,
            auth_key=auth_key,
            frag_key=frag_key
        )
        dns_query = frag.serialize()

        assert isinstance(dns_query, str)
        assert dns_query.endswith('.test.com')

    def test_base36_label_is_63_chars(self, enc_key, auth_key, frag_key):
        """Base36 label should be padded to 63 characters."""
        frag = DnsFragment(
            domain='.test.com',
            packet_id=1,
            frag_index=0,
            is_first=True,
            has_more=False,
            frag_data=b'test',
            enc_key=enc_key,
            auth_key=auth_key,
            frag_key=frag_key
        )
        dns_query = frag.serialize()

        base36_part = dns_query[:-len('.test.com')]
        assert len(base36_part) == BASE36_PACKET_SIZE

    def test_deserialize_dns_query(self, enc_key, auth_key, frag_key):
        """Test deserialization from DNS query string."""
        original = DnsFragment(
            domain='.test.com',
            packet_id=0xCAFEBABE,
            frag_index=3,
            is_first=False,
            has_more=True,
            frag_data=b'payload data',
            enc_key=enc_key,
            auth_key=auth_key,
            frag_key=frag_key
        )
        dns_query = original.serialize()

        recovered = original.deserialize(dns_query)

        assert recovered._packet_id == 0xCAFEBABE
        assert recovered._frag_index == 3
        assert recovered._is_first is False
        assert recovered._has_more is True
        # Non-last fragment: payload is padded to 28 bytes (not stripped)
        assert recovered._frag_data == b'payload data' + b'\x00' * (FRAGMENT_PAYLOAD_SIZE - 12)

    def test_deserialize_wrong_domain_returns_none(self, enc_key, auth_key, frag_key):
        """Wrong domain suffix should return None."""
        frag = DnsFragment(
            domain='.test.com',
            enc_key=enc_key,
            auth_key=auth_key,
            frag_key=frag_key
        )
        result = frag.deserialize('something.wrong.org')
        assert result is None

    def test_deserialize_invalid_base36_returns_none(self, enc_key, auth_key, frag_key):
        """Invalid base36 characters should return None."""
        frag = DnsFragment(
            domain='.test.com',
            enc_key=enc_key,
            auth_key=auth_key,
            frag_key=frag_key
        )
        # ! is not valid in base36
        result = frag.deserialize('INVALID!CHARS.test.com')
        assert result is None

    def test_deserialize_handles_short_base36(self, enc_key, auth_key, frag_key):
        """Short base36 should be padded with leading zeros."""
        # Create a fragment with small packet_id that results in short base36
        frag = DnsFragment(
            domain='.test.com',
            packet_id=1,  # Small value
            frag_index=0,
            is_first=True,
            has_more=False,
            frag_data=b'x',
            enc_key=enc_key,
            auth_key=auth_key,
            frag_key=frag_key
        )
        dns_query = frag.serialize()

        # Should still work
        recovered = frag.deserialize(dns_query)
        assert recovered is not None
        assert recovered._packet_id == 1

    def test_base36_is_uppercase(self, enc_key, auth_key, frag_key):
        """Base36 encoding should use uppercase letters."""
        frag = DnsFragment(
            domain='.test.com',
            packet_id=0xFFFFFFFF,  # High value to ensure letters
            frag_index=0,
            is_first=True,
            has_more=False,
            frag_data=b'\xff' * 28,  # High values
            enc_key=enc_key,
            auth_key=auth_key,
            frag_key=frag_key
        )
        dns_query = frag.serialize()
        base36_part = dns_query[:-len('.test.com')]

        # Should contain uppercase letters or digits only
        for char in base36_part:
            assert char in '0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ'


class TestEncryptedFragmentMessage:
    """Test message-level encryption/decryption."""

    def test_encrypt_message(self, enc_key, auth_key):
        """Test message encryption."""
        plaintext = b'key=value pair'
        encrypted = EncryptedFragment.encrypt_message(enc_key, auth_key, plaintext)

        # Should have nonce (8) + integrity (8) + ciphertext
        assert len(encrypted) == 8 + 8 + len(plaintext)

    def test_decrypt_message(self, enc_key, auth_key):
        """Test message decryption."""
        plaintext = b'test message data'
        encrypted = EncryptedFragment.encrypt_message(enc_key, auth_key, plaintext)
        decrypted = EncryptedFragment.decrypt_message(enc_key, auth_key, encrypted)

        assert decrypted == plaintext

    def test_encrypt_decrypt_round_trip(self, enc_key, auth_key):
        """Test encrypt/decrypt round trip."""
        for length in [1, 10, 50, 100, 500]:
            plaintext = secrets.token_bytes(length)
            encrypted = EncryptedFragment.encrypt_message(enc_key, auth_key, plaintext)
            decrypted = EncryptedFragment.decrypt_message(enc_key, auth_key, encrypted)
            assert decrypted == plaintext

    def test_encryption_is_nondeterministic(self, enc_key, auth_key):
        """Same plaintext should encrypt to different ciphertext (random nonce)."""
        plaintext = b'test'
        encrypted1 = EncryptedFragment.encrypt_message(enc_key, auth_key, plaintext)
        encrypted2 = EncryptedFragment.encrypt_message(enc_key, auth_key, plaintext)

        # Nonces should be different
        assert encrypted1[:8] != encrypted2[:8]
        # Ciphertexts should be different
        assert encrypted1 != encrypted2
        # But both should decrypt to same plaintext
        assert EncryptedFragment.decrypt_message(enc_key, auth_key, encrypted1) == plaintext
        assert EncryptedFragment.decrypt_message(enc_key, auth_key, encrypted2) == plaintext

    def test_decrypt_corrupted_returns_none(self, enc_key, auth_key):
        """Corrupted message should fail integrity check and return None."""
        plaintext = b'test message'
        encrypted = bytearray(EncryptedFragment.encrypt_message(enc_key, auth_key, plaintext))

        # Corrupt the ciphertext (after nonce and integrity)
        encrypted[16] ^= 0xFF

        result = EncryptedFragment.decrypt_message(enc_key, auth_key, bytes(encrypted))
        assert result is None

    def test_decrypt_bad_integrity_returns_none(self, enc_key, auth_key):
        """Bad integrity MAC should return None."""
        plaintext = b'test message'
        encrypted = bytearray(EncryptedFragment.encrypt_message(enc_key, auth_key, plaintext))

        # Corrupt integrity MAC (bytes 8-16)
        encrypted[8] ^= 0xFF

        result = EncryptedFragment.decrypt_message(enc_key, auth_key, bytes(encrypted))
        assert result is None

    def test_decrypt_too_short_returns_none(self, enc_key, auth_key):
        """Message shorter than header should return None."""
        # Minimum is 16 bytes (8 nonce + 8 integrity)
        result = EncryptedFragment.decrypt_message(enc_key, auth_key, b'short')
        assert result is None

    def test_empty_plaintext(self, enc_key, auth_key):
        """Empty plaintext should still work."""
        encrypted = EncryptedFragment.encrypt_message(enc_key, auth_key, b'')
        decrypted = EncryptedFragment.decrypt_message(enc_key, auth_key, encrypted)
        assert decrypted == b''


class TestFragmentEdgeCases:
    """Test edge cases and boundary conditions."""

    def test_max_packet_id(self, enc_key, frag_key):
        """Maximum u32 packet ID should work."""
        frag = Fragment(
            packet_id=0xFFFFFFFF,
            frag_index=0,
            is_first=True,
            has_more=False,
            frag_data=b'x',
            enc_key=enc_key,
            frag_key=frag_key
        )
        recovered = frag.deserialize(frag.serialize())
        assert recovered._packet_id == 0xFFFFFFFF

    def test_zero_packet_id(self, enc_key, frag_key):
        """Zero packet ID should work."""
        frag = Fragment(
            packet_id=0,
            frag_index=0,
            is_first=True,
            has_more=False,
            frag_data=b'x',
            enc_key=enc_key,
            frag_key=frag_key
        )
        recovered = frag.deserialize(frag.serialize())
        assert recovered._packet_id == 0

    def test_empty_payload(self, enc_key, frag_key):
        """Empty fragment payload should work."""
        frag = Fragment(
            packet_id=1,
            frag_index=0,
            is_first=True,
            has_more=False,
            frag_data=b'',
            enc_key=enc_key,
            frag_key=frag_key
        )
        recovered = frag.deserialize(frag.serialize())
        # Last fragment (has_more=False): trailing zeros stripped → empty
        assert recovered._frag_data == b''

    def test_max_payload_size(self, enc_key, frag_key):
        """Maximum payload size (28 bytes) should work."""
        payload = secrets.token_bytes(FRAGMENT_PAYLOAD_SIZE)
        frag = Fragment(
            packet_id=1,
            frag_index=0,
            is_first=True,
            has_more=False,
            frag_data=payload,
            enc_key=enc_key,
            frag_key=frag_key
        )
        recovered = frag.deserialize(frag.serialize())
        assert recovered._frag_data == payload

    def test_various_fragment_indices(self, enc_key, frag_key):
        """Various fragment indices should work."""
        for index in [0, 1, 100, 1000, 0x3FFFFFFF]:
            frag = Fragment(
                packet_id=1,
                frag_index=index,
                is_first=(index == 0),
                has_more=True,
                frag_data=b'x',
                enc_key=enc_key,
                frag_key=frag_key
            )
            recovered = frag.deserialize(frag.serialize())
            assert recovered._frag_index == index
