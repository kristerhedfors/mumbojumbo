#!/usr/bin/env python3
"""Tests for cryptographic primitives in mumbojumbo v2.0 protocol.

Tests ChaCha20, Poly1305, and base36 encoding implementations.
"""

import secrets
import struct

import pytest

from mumbojumbo import (
    chacha20_encrypt,
    chacha20_decrypt,
    poly1305_mac,
    base36_encode,
    base36_decode,
    derive_keys,
    encode_key_hex,
    decode_key_hex,
)


class TestChaCha20:
    """Test ChaCha20 encryption/decryption."""

    def test_encrypt_decrypt_round_trip(self):
        """Test that encrypt and decrypt are inverses."""
        key = secrets.token_bytes(32)
        nonce = secrets.token_bytes(8)
        plaintext = b'Hello, World!'

        ciphertext = chacha20_encrypt(key, nonce, plaintext)
        decrypted = chacha20_decrypt(key, nonce, ciphertext)

        assert decrypted == plaintext

    def test_different_nonces_produce_different_ciphertext(self):
        """Different nonces should produce different ciphertexts."""
        key = secrets.token_bytes(32)
        nonce1 = secrets.token_bytes(8)
        nonce2 = secrets.token_bytes(8)
        plaintext = b'test'

        ciphertext1 = chacha20_encrypt(key, nonce1, plaintext)
        ciphertext2 = chacha20_encrypt(key, nonce2, plaintext)

        assert ciphertext1 != ciphertext2

    def test_different_keys_produce_different_ciphertext(self):
        """Different keys should produce different ciphertexts."""
        key1 = secrets.token_bytes(32)
        key2 = secrets.token_bytes(32)
        nonce = secrets.token_bytes(8)
        plaintext = b'test'

        ciphertext1 = chacha20_encrypt(key1, nonce, plaintext)
        ciphertext2 = chacha20_encrypt(key2, nonce, plaintext)

        assert ciphertext1 != ciphertext2

    def test_output_same_length_as_input(self):
        """ChaCha20 output should be same length as input."""
        key = secrets.token_bytes(32)
        nonce = secrets.token_bytes(8)

        for length in [0, 1, 15, 16, 63, 64, 65, 100, 1000]:
            plaintext = secrets.token_bytes(length)
            ciphertext = chacha20_encrypt(key, nonce, plaintext)
            assert len(ciphertext) == length

    def test_12_byte_nonce_supported(self):
        """12-byte nonce should be supported."""
        key = secrets.token_bytes(32)
        nonce = secrets.token_bytes(12)
        plaintext = b'test'

        ciphertext = chacha20_encrypt(key, nonce, plaintext)
        decrypted = chacha20_decrypt(key, nonce, ciphertext)

        assert decrypted == plaintext

    def test_invalid_key_length_raises(self):
        """Invalid key length should raise ValueError."""
        with pytest.raises(ValueError, match='Key must be 32 bytes'):
            chacha20_encrypt(b'short', secrets.token_bytes(8), b'test')

    def test_invalid_nonce_length_raises(self):
        """Invalid nonce length should raise ValueError."""
        key = secrets.token_bytes(32)
        with pytest.raises(ValueError, match='Nonce must be 8 or 12 bytes'):
            chacha20_encrypt(key, b'bad', b'test')

    def test_empty_plaintext(self):
        """Empty plaintext should return empty ciphertext."""
        key = secrets.token_bytes(32)
        nonce = secrets.token_bytes(8)

        ciphertext = chacha20_encrypt(key, nonce, b'')
        assert ciphertext == b''

    def test_deterministic_for_same_inputs(self):
        """Same key/nonce/plaintext should produce same ciphertext."""
        key = secrets.token_bytes(32)
        nonce = secrets.token_bytes(8)
        plaintext = b'test data'

        ciphertext1 = chacha20_encrypt(key, nonce, plaintext)
        ciphertext2 = chacha20_encrypt(key, nonce, plaintext)

        assert ciphertext1 == ciphertext2


class TestPoly1305:
    """Test Poly1305 MAC computation."""

    def test_mac_is_16_bytes(self):
        """Poly1305 MAC should always be 16 bytes."""
        key = secrets.token_bytes(32)

        for msg_len in [0, 1, 15, 16, 17, 100, 1000]:
            msg = secrets.token_bytes(msg_len)
            mac = poly1305_mac(key, msg)
            assert len(mac) == 16

    def test_different_keys_produce_different_macs(self):
        """Different keys should produce different MACs."""
        key1 = secrets.token_bytes(32)
        key2 = secrets.token_bytes(32)
        msg = b'test message'

        mac1 = poly1305_mac(key1, msg)
        mac2 = poly1305_mac(key2, msg)

        assert mac1 != mac2

    def test_different_messages_produce_different_macs(self):
        """Different messages should produce different MACs."""
        key = secrets.token_bytes(32)
        msg1 = b'message one'
        msg2 = b'message two'

        mac1 = poly1305_mac(key, msg1)
        mac2 = poly1305_mac(key, msg2)

        assert mac1 != mac2

    def test_deterministic_for_same_inputs(self):
        """Same key/message should produce same MAC."""
        key = secrets.token_bytes(32)
        msg = b'test message'

        mac1 = poly1305_mac(key, msg)
        mac2 = poly1305_mac(key, msg)

        assert mac1 == mac2

    def test_invalid_key_length_raises(self):
        """Invalid key length should raise ValueError."""
        with pytest.raises(ValueError, match='Key must be 32 bytes'):
            poly1305_mac(b'short', b'test')

    def test_empty_message(self):
        """Empty message should still produce 16-byte MAC."""
        key = secrets.token_bytes(32)
        mac = poly1305_mac(key, b'')
        assert len(mac) == 16

    def test_bit_flip_changes_mac(self):
        """Flipping a single bit in message should change MAC."""
        key = secrets.token_bytes(32)
        msg = bytearray(b'test message')
        mac1 = poly1305_mac(key, bytes(msg))

        # Flip one bit
        msg[0] ^= 1
        mac2 = poly1305_mac(key, bytes(msg))

        assert mac1 != mac2


class TestBase36:
    """Test base36 encoding/decoding."""

    def test_encode_decode_round_trip(self):
        """Test that encode and decode are inverses."""
        for length in [1, 5, 10, 40, 100]:
            data = secrets.token_bytes(length)
            encoded = base36_encode(data)
            decoded = base36_decode(encoded)
            # May have leading zeros stripped, so compare values
            assert int.from_bytes(data, 'big') == int.from_bytes(decoded, 'big')

    def test_40_bytes_to_63_chars(self):
        """40 bytes should encode to ~63 characters in base36."""
        data = secrets.token_bytes(40)
        encoded = base36_encode(data)
        # 40 bytes = 320 bits, log36(2^320) ≈ 62.01, so 62-63 chars
        assert 61 <= len(encoded) <= 63

    def test_uppercase_alphabet(self):
        """Base36 should use uppercase letters."""
        data = b'\xff' * 10  # High values to ensure letters used
        encoded = base36_encode(data)
        # Should be uppercase or digits only
        assert all(c in '0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ' for c in encoded)

    def test_decode_case_insensitive(self):
        """Decoding should be case-insensitive."""
        data = secrets.token_bytes(20)
        encoded = base36_encode(data)

        decoded_upper = base36_decode(encoded.upper())
        decoded_lower = base36_decode(encoded.lower())

        assert decoded_upper == decoded_lower

    def test_encode_empty_returns_zero(self):
        """Empty data should encode to '0'."""
        encoded = base36_encode(b'')
        assert encoded == '0'

    def test_encode_zero_byte(self):
        """Zero byte should encode to '0'."""
        encoded = base36_encode(b'\x00')
        assert encoded == '0'

    def test_decode_zero(self):
        """Decoding '0' should return zero byte."""
        decoded = base36_decode('0')
        assert decoded == b'\x00'

    def test_invalid_character_raises(self):
        """Invalid base36 character should raise ValueError."""
        with pytest.raises(ValueError, match='Invalid base36 character'):
            base36_decode('HELLO!')

    def test_specific_values(self):
        """Test specific known conversions."""
        # Single digit
        assert base36_encode(b'\x09') == '9'
        assert base36_encode(b'\x0a') == 'A'
        assert base36_encode(b'\x23') == 'Z'  # 35 = Z in base36

        # Verify decoding
        assert int.from_bytes(base36_decode('Z'), 'big') == 35


class TestKeyDerivation:
    """Test key derivation from client key."""

    def test_derive_keys_returns_three_keys(self):
        """derive_keys should return three 32-byte keys."""
        client_key = secrets.token_bytes(32)
        enc_key, auth_key, frag_key = derive_keys(client_key)

        assert len(enc_key) == 32
        assert len(auth_key) == 32
        assert len(frag_key) == 32

    def test_derived_keys_are_different(self):
        """Each derived key should be different."""
        client_key = secrets.token_bytes(32)
        enc_key, auth_key, frag_key = derive_keys(client_key)

        assert enc_key != auth_key
        assert auth_key != frag_key
        assert enc_key != frag_key

    def test_derivation_is_deterministic(self):
        """Same client key should derive same keys."""
        client_key = secrets.token_bytes(32)

        enc1, auth1, frag1 = derive_keys(client_key)
        enc2, auth2, frag2 = derive_keys(client_key)

        assert enc1 == enc2
        assert auth1 == auth2
        assert frag1 == frag2

    def test_different_client_keys_derive_different_keys(self):
        """Different client keys should derive different keys."""
        client_key1 = secrets.token_bytes(32)
        client_key2 = secrets.token_bytes(32)

        enc1, auth1, frag1 = derive_keys(client_key1)
        enc2, auth2, frag2 = derive_keys(client_key2)

        assert enc1 != enc2
        assert auth1 != auth2
        assert frag1 != frag2

    def test_invalid_client_key_length_raises(self):
        """Invalid client key length should raise ValueError."""
        with pytest.raises(ValueError, match='Client key must be 32 bytes'):
            derive_keys(b'short')


class TestKeyEncoding:
    """Test key hex encoding/decoding with prefixes."""

    def test_encode_client_key(self):
        """Test encoding with mj_cli_ prefix."""
        key_bytes = secrets.token_bytes(32)
        encoded = encode_key_hex(key_bytes, key_type='cli')

        assert encoded.startswith('mj_cli_')
        assert len(encoded) == 71  # mj_cli_ (7) + 64 hex chars

    def test_decode_client_key(self):
        """Test decoding mj_cli_ prefixed key."""
        key_bytes = secrets.token_bytes(32)
        encoded = encode_key_hex(key_bytes, key_type='cli')
        decoded = decode_key_hex(encoded)

        assert decoded == key_bytes

    def test_round_trip(self):
        """Test encode/decode round trip."""
        key_bytes = secrets.token_bytes(32)
        encoded = encode_key_hex(key_bytes, key_type='cli')
        decoded = decode_key_hex(encoded)

        assert decoded == key_bytes

    def test_decode_raw_hex(self):
        """Test decoding raw hex without prefix."""
        key_bytes = secrets.token_bytes(32)
        hex_str = key_bytes.hex()
        decoded = decode_key_hex(hex_str)

        assert decoded == key_bytes

    def test_invalid_key_length_encode_raises(self):
        """Encoding non-32-byte key should raise ValueError."""
        with pytest.raises(ValueError, match='Key must be 32 bytes'):
            encode_key_hex(b'short', key_type='cli')

    def test_invalid_hex_decode_raises(self):
        """Invalid hex in key should raise ValueError."""
        with pytest.raises(ValueError, match='Invalid hex string'):
            decode_key_hex('mj_cli_' + 'ZZZZ' * 16)  # Z is not valid hex

    def test_wrong_length_hex_decode_raises(self):
        """Wrong length hex should raise ValueError."""
        with pytest.raises(ValueError, match='Key must be 32 bytes'):
            decode_key_hex('mj_cli_' + 'aa' * 10)  # Too short
