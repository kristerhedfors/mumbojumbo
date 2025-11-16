#!/usr/bin/env python3
"""
ChaCha20-Poly1305 and Base36 Implementation & Validation

This standalone script implements ChaCha20, Poly1305, and Base36 encoding
from scratch using only Python standard library. It validates correctness
against the cryptography library.

References:
- RFC 7539: ChaCha20 and Poly1305 for IETF Protocols
- RFC 8439: ChaCha20-Poly1305 AEAD
"""

import struct
import sys


# ============================================================================
# ChaCha20 Implementation (RFC 7539)
# ============================================================================

def rotl32(v, c):
    """Rotate left: 32-bit value v by c bits."""
    return ((v << c) & 0xffffffff) | (v >> (32 - c))


def quarter_round(state, a, b, c, d):
    """ChaCha20 quarter round on indices a, b, c, d."""
    state[a] = (state[a] + state[b]) & 0xffffffff
    state[d] ^= state[a]
    state[d] = rotl32(state[d], 16)

    state[c] = (state[c] + state[d]) & 0xffffffff
    state[b] ^= state[c]
    state[b] = rotl32(state[b], 12)

    state[a] = (state[a] + state[b]) & 0xffffffff
    state[d] ^= state[a]
    state[d] = rotl32(state[d], 8)

    state[c] = (state[c] + state[d]) & 0xffffffff
    state[b] ^= state[c]
    state[b] = rotl32(state[b], 7)


def chacha20_block(key, counter, nonce):
    """
    Generate a 64-byte ChaCha20 keystream block.

    Args:
        key: 32-byte key
        counter: 4-byte counter (int)
        nonce: 12-byte nonce

    Returns:
        64-byte keystream block
    """
    # Build initial state
    # Constants "expand 32-byte k"
    constants = [0x61707865, 0x3320646e, 0x79622d32, 0x6b206574]

    # Key (8 words)
    key_words = list(struct.unpack('<8I', key))

    # Counter (1 word)
    counter_word = counter & 0xffffffff

    # Nonce (3 words)
    nonce_words = list(struct.unpack('<3I', nonce))

    # Initial state: 16 words
    state = constants + key_words + [counter_word] + nonce_words
    working_state = state[:]

    # 20 rounds (10 double rounds)
    for _ in range(10):
        # Column rounds
        quarter_round(working_state, 0, 4, 8, 12)
        quarter_round(working_state, 1, 5, 9, 13)
        quarter_round(working_state, 2, 6, 10, 14)
        quarter_round(working_state, 3, 7, 11, 15)

        # Diagonal rounds
        quarter_round(working_state, 0, 5, 10, 15)
        quarter_round(working_state, 1, 6, 11, 12)
        quarter_round(working_state, 2, 7, 8, 13)
        quarter_round(working_state, 3, 4, 9, 14)

    # Add original state
    for i in range(16):
        working_state[i] = (working_state[i] + state[i]) & 0xffffffff

    # Serialize to bytes (little-endian)
    return struct.pack('<16I', *working_state)


def chacha20_encrypt(key, nonce, plaintext, counter=0):
    """
    Encrypt/decrypt with ChaCha20.

    Args:
        key: 32-byte key
        nonce: 8 or 12-byte nonce (8-byte will be zero-padded)
        plaintext: Data to encrypt
        counter: Starting counter value (default 0)

    Returns:
        Ciphertext (same length as plaintext)
    """
    # Handle 8-byte nonce by zero-padding to 12 bytes
    if len(nonce) == 8:
        nonce = nonce + b'\x00\x00\x00\x00'
    elif len(nonce) != 12:
        raise ValueError(f"Nonce must be 8 or 12 bytes, got {len(nonce)}")

    if len(key) != 32:
        raise ValueError(f"Key must be 32 bytes, got {len(key)}")

    keystream = b''
    blocks_needed = (len(plaintext) + 63) // 64

    for i in range(blocks_needed):
        keystream += chacha20_block(key, counter + i, nonce)

    # XOR plaintext with keystream
    keystream = keystream[:len(plaintext)]
    return bytes(p ^ k for p, k in zip(plaintext, keystream))


# ChaCha20 decrypt is same as encrypt (XOR is symmetric)
chacha20_decrypt = chacha20_encrypt


# ============================================================================
# Poly1305 Implementation (RFC 7539)
# ============================================================================

def poly1305_mac(key, msg):
    """
    Compute Poly1305 MAC.

    Args:
        key: 32-byte key (first 16 bytes = r, last 16 bytes = s)
        msg: Message to authenticate

    Returns:
        16-byte MAC tag
    """
    if len(key) != 32:
        raise ValueError(f"Key must be 32 bytes, got {len(key)}")

    # Split key into r and s
    r_bytes = key[:16]
    s_bytes = key[16:32]

    # Clamp r
    r = int.from_bytes(r_bytes, 'little')
    r &= 0x0ffffffc0ffffffc0ffffffc0fffffff

    # Convert s to integer
    s = int.from_bytes(s_bytes, 'little')

    # Prime for field arithmetic
    p = (1 << 130) - 5

    # Process message in 16-byte blocks
    accumulator = 0

    for i in range(0, len(msg), 16):
        # Get block (pad if needed)
        block = msg[i:i+16]

        # Convert to integer (little-endian) and add 0x01 byte at the end
        if len(block) == 16:
            n = int.from_bytes(block + b'\x01', 'little')
        else:
            # Last block (< 16 bytes): add 0x01 after the block
            n = int.from_bytes(block + b'\x01', 'little')

        # Accumulate
        accumulator = ((accumulator + n) * r) % p

    # Add s
    accumulator = (accumulator + s) % (1 << 128)

    # Convert to bytes (little-endian)
    return accumulator.to_bytes(16, 'little')


# ============================================================================
# Base36 Implementation
# ============================================================================

BASE36_ALPHABET = '0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ'


def base36_encode(data):
    """
    Encode bytes to base36 string (uppercase).

    Args:
        data: Bytes to encode

    Returns:
        Base36 string (uppercase)
    """
    if not data:
        return '0'

    # Convert bytes to big integer
    num = int.from_bytes(data, 'big')

    if num == 0:
        return '0'

    # Convert to base36
    result = []
    while num > 0:
        num, remainder = divmod(num, 36)
        result.append(BASE36_ALPHABET[remainder])

    return ''.join(reversed(result))


def base36_decode(s):
    """
    Decode base36 string to bytes.

    Args:
        s: Base36 string (case-insensitive)

    Returns:
        Decoded bytes
    """
    s = s.upper().strip()

    # Convert base36 to integer
    num = 0
    for char in s:
        if char not in BASE36_ALPHABET:
            raise ValueError(f"Invalid base36 character: {char}")
        num = num * 36 + BASE36_ALPHABET.index(char)

    # Convert integer to bytes
    # Calculate byte length needed
    if num == 0:
        return b'\x00'

    byte_length = (num.bit_length() + 7) // 8
    return num.to_bytes(byte_length, 'big')


# ============================================================================
# Validation Against cryptography Library
# ============================================================================

def validate_chacha20():
    """Validate ChaCha20 implementation against RFC 7539 test vectors."""
    print("=" * 70)
    print("ChaCha20 Validation (RFC 7539 Test Vectors)")
    print("=" * 70)

    # RFC 7539 Section 2.4.2 - ChaCha20 Encryption Test Vector
    rfc_test = {
        'name': 'RFC 7539 Section 2.4.2',
        'key': bytes.fromhex('000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f'),
        'nonce': bytes.fromhex('000000000000004a00000000'),  # 12 bytes
        'counter': 1,
        'plaintext': b"Ladies and Gentlemen of the class of '99: If I could offer you only one tip for the future, sunscreen would be it.",
        'expected': bytes.fromhex(
            '6e2e359a2568f98041ba0728dd0d6981'
            'e97e7aec1d4360c20a27afccfd9fae0b'
            'f91b65c5524733ab8f593dabcd62b357'
            '1639d624e65152ab8f530c359f0861d8'
            '07ca0dbf500d6a6156a38e088a22b65e'
            '52bc514d16ccf806818ce91ab7793736'
            '5af90bbf74a35be6b40b8eedf2785e42'
            '874d'
        )
    }

    all_passed = True

    # Test RFC vector
    print(f"\nTest 1: {rfc_test['name']}")
    our_ciphertext = chacha20_encrypt(
        rfc_test['key'],
        rfc_test['nonce'],
        rfc_test['plaintext'],
        rfc_test['counter']
    )

    if our_ciphertext == rfc_test['expected']:
        print(f"  ✅ PASS - Matches RFC 7539 test vector")
    else:
        print(f"  ❌ FAIL - Does not match RFC 7539")
        print(f"     Expected: {rfc_test['expected'].hex()}")
        print(f"     Got:      {our_ciphertext.hex()}")
        all_passed = False

    # Test 8-byte nonce (zero-padded)
    print(f"\nTest 2: 8-byte nonce (zero-padded to 12 bytes)")
    key = b'\x00' * 32
    nonce_8 = b'\x00' * 8
    plaintext = b'Testing 8-byte nonce'

    # Encrypt with 8-byte nonce
    ciphertext_8 = chacha20_encrypt(key, nonce_8, plaintext, 0)

    # Should be same as 12-byte nonce with trailing zeros
    nonce_12 = nonce_8 + b'\x00\x00\x00\x00'
    ciphertext_12 = chacha20_encrypt(key, nonce_12, plaintext, 0)

    if ciphertext_8 == ciphertext_12:
        print(f"  ✅ PASS - 8-byte nonce correctly zero-padded")
    else:
        print(f"  ❌ FAIL - 8-byte nonce padding issue")
        all_passed = False

    # Test round-trip
    print(f"\nTest 3: Encryption/Decryption Round-Trip")
    key = b'A' * 32
    nonce = b'B' * 12
    plaintext = b'The quick brown fox jumps over the lazy dog'

    ciphertext = chacha20_encrypt(key, nonce, plaintext, 0)
    decrypted = chacha20_decrypt(key, nonce, ciphertext, 0)

    if decrypted == plaintext:
        print(f"  ✅ PASS - Round-trip successful")
    else:
        print(f"  ❌ FAIL - Round-trip failed")
        print(f"     Original:  {plaintext}")
        print(f"     Decrypted: {decrypted}")
        all_passed = False

    return all_passed


def validate_poly1305():
    """Validate Poly1305 implementation against cryptography library."""
    print("\n" + "=" * 70)
    print("Poly1305 Validation")
    print("=" * 70)

    try:
        from cryptography.hazmat.primitives import poly1305
        from cryptography.hazmat.backends import default_backend
    except ImportError:
        print("❌ cryptography library not installed. Skipping validation.")
        return False

    test_cases = [
        {
            'name': 'Empty message',
            'key': b'\x00' * 32,
            'msg': b''
        },
        {
            'name': 'Short message',
            'key': b'\x01' * 32,
            'msg': b'Hello'
        },
        {
            'name': 'Exact 16-byte block',
            'key': b'\x42' * 32,
            'msg': b'A' * 16
        },
        {
            'name': 'Multiple blocks',
            'key': b'\xff' * 32,
            'msg': b'The quick brown fox jumps over the lazy dog'
        }
    ]

    all_passed = True

    for i, test in enumerate(test_cases, 1):
        print(f"\nTest {i}: {test['name']}")

        key = test['key']
        msg = test['msg']

        # Our implementation
        our_tag = poly1305_mac(key, msg)

        # cryptography library
        p = poly1305.Poly1305(key)
        p.update(msg)
        lib_tag = p.finalize()

        if our_tag == lib_tag:
            print(f"  ✅ PASS - Tags match: {our_tag.hex()}")
        else:
            print(f"  ❌ FAIL - Tags differ")
            print(f"     Our:     {our_tag.hex()}")
            print(f"     Library: {lib_tag.hex()}")
            all_passed = False

    return all_passed


def validate_base36():
    """Validate Base36 encoding/decoding."""
    print("\n" + "=" * 70)
    print("Base36 Validation")
    print("=" * 70)

    test_cases = [
        {
            'name': '40 bytes (protocol packet size)',
            'data': b'\x00' * 40
        },
        {
            'name': '40 bytes (all ones)',
            'data': b'\xff' * 40
        },
        {
            'name': '40 bytes (pattern)',
            'data': bytes(range(40))
        },
        {
            'name': 'Random 40 bytes',
            'data': b'\x42\x24\xde\xad\xbe\xef' * 6 + b'\xca\xfe\xba\xbe'
        }
    ]

    all_passed = True

    for i, test in enumerate(test_cases, 1):
        print(f"\nTest {i}: {test['name']}")

        data = test['data']

        # Encode
        encoded = base36_encode(data)
        print(f"  Encoded length: {len(encoded)} chars")
        print(f"  Encoded: {encoded}")

        # Check length for 40-byte input
        if len(data) == 40:
            if len(encoded) <= 63:
                print(f"  ✅ Length ≤ 63 (fits in DNS label)")
            else:
                print(f"  ❌ Length > 63 (TOO LONG for DNS label)")
                all_passed = False

        # Decode
        decoded = base36_decode(encoded)

        # Pad decoded to match original length (leading zeros may be lost)
        if len(decoded) < len(data):
            decoded = b'\x00' * (len(data) - len(decoded)) + decoded

        # Verify round-trip
        if decoded == data:
            print(f"  ✅ Round-trip PASS")
        else:
            print(f"  ❌ Round-trip FAIL")
            print(f"     Original: {data.hex()}")
            print(f"     Decoded:  {decoded.hex()}")
            all_passed = False

    # Test case-insensitivity
    print(f"\nTest: Case insensitivity")
    encoded_upper = base36_encode(b'Test')
    encoded_lower = encoded_upper.lower()
    decoded_upper = base36_decode(encoded_upper)
    decoded_lower = base36_decode(encoded_lower)

    if decoded_upper == decoded_lower:
        print(f"  ✅ Case-insensitive decoding works")
    else:
        print(f"  ❌ Case-insensitive decoding failed")
        all_passed = False

    return all_passed


# ============================================================================
# Main Validation
# ============================================================================

def main():
    """Run all validation tests."""
    print("\n" + "=" * 70)
    print("ChaCha20-Poly1305 & Base36 Implementation Validation")
    print("=" * 70)
    print()

    results = []

    # Validate ChaCha20
    results.append(('ChaCha20', validate_chacha20()))

    # Validate Poly1305
    results.append(('Poly1305', validate_poly1305()))

    # Validate Base36
    results.append(('Base36', validate_base36()))

    # Summary
    print("\n" + "=" * 70)
    print("Validation Summary")
    print("=" * 70)

    all_passed = True
    for name, passed in results:
        status = "✅ PASS" if passed else "❌ FAIL"
        print(f"{name:20s} {status}")
        if not passed:
            all_passed = False

    print()

    if all_passed:
        print("🎉 All validations passed!")
        return 0
    else:
        print("⚠️  Some validations failed. Review output above.")
        return 1


if __name__ == '__main__':
    sys.exit(main())
