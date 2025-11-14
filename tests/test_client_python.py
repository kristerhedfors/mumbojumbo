#!/usr/bin/env python3
"""
Comprehensive tests for Python mumbojumbo client.

Tests cover:
- Fragment creation and serialization
- Encryption/decryption round-trips
- Base32 encoding
- DNS query generation
- Single and multi-fragment messages
- Edge cases and error handling
- End-to-end integration with server
"""

import sys
import os
import struct
import base64
import subprocess
import tempfile
import pytest
import nacl.public

# Import client module
client_path = os.path.join(os.path.dirname(__file__), '..', 'clients', 'python', 'mumbojumbo-client.py')
import importlib.util
spec = importlib.util.spec_from_file_location("mumbojumbo_client", client_path)
client = importlib.util.module_from_spec(spec)
spec.loader.exec_module(client)


class TestKeyParsing:
    """Test public key parsing through MumbojumboClient constructor."""

    def test_parse_valid_key(self):
        """Valid key should parse correctly through constructor."""
        key_str = 'mj_cli_' + 'a' * 64
        # Test that client can be created with hex key string
        client_obj = client.MumbojumboClient(key_str, '.test')
        assert client_obj.server_client_key is not None
        assert len(bytes(client_obj.server_client_key)) == 32

    def test_parse_key_wrong_prefix(self):
        """Key without mj_cli_ prefix should fail."""
        with pytest.raises(ValueError, match='must start with'):
            client.MumbojumboClient('wrong_prefix_' + 'a' * 64, '.test')

    def test_parse_key_wrong_length(self):
        """Key with wrong hex length should fail."""
        with pytest.raises(ValueError, match='Invalid hex key length'):
            client.MumbojumboClient('mj_cli_' + 'a' * 60, '.test')

    def test_parse_key_invalid_hex(self):
        """Key with invalid hex characters should fail."""
        with pytest.raises(ValueError, match='Invalid hex'):
            client.MumbojumboClient('mj_cli_' + 'z' * 64, '.test')


class TestFragmentCreation:
    """Test fragment header creation."""

    def test_basic_fragment(self):
        """Test basic fragment creation."""
        packet_id = 0x1234
        frag_index = 0
        frag_count = 1
        frag_data = b"HI"

        fragment = client.create_fragment(packet_id, frag_index, frag_count, frag_data)

        # Verify header (18 bytes: u64 + u32 + u32 + u8 + u8)
        assert len(fragment) == 20  # 18 byte header + 2 byte data
        assert fragment[:8] == b'\x00\x00\x00\x00\x00\x00\x12\x34'  # packet_id big-endian u64
        assert fragment[8:12] == b'\x00\x00\x00\x00'  # frag_index u32
        assert fragment[12:16] == b'\x00\x00\x00\x01'  # frag_count u32
        assert fragment[16:17] == b'\x02'  # data_len u8
        assert fragment[17:18] == b'\x00'  # key_len u8 (default 0)
        assert fragment[18:] == b"HI"

    def test_multi_fragment(self):
        """Test multi-fragment packet header."""
        packet_id = 0xDEAD
        frag_index = 1
        frag_count = 3
        frag_data = b"test"

        fragment = client.create_fragment(packet_id, frag_index, frag_count, frag_data)

        # Verify header fields (18 bytes: u64 + u32 + u32 + u8 + u8)
        pid, fidx, fcnt, flen, klen = struct.unpack('!QIIBB', fragment[:18])
        assert pid == 0xDEAD
        assert fidx == 1
        assert fcnt == 3
        assert flen == 4
        assert klen == 0

    def test_empty_fragment(self):
        """Test empty fragment data."""
        fragment = client.create_fragment(0x0001, 0, 1, b'')
        assert len(fragment) == 18  # Just header (18 bytes)
        assert fragment[16:17] == b'\x00'  # data_len = 0
        assert fragment[17:18] == b'\x00'  # key_len = 0

    def test_max_size_fragment(self):
        """Test maximum size fragment."""
        frag_data = b'X' * client.MAX_FRAG_DATA_LEN
        fragment = client.create_fragment(0x0001, 0, 1, frag_data)
        assert len(fragment) == 18 + client.MAX_FRAG_DATA_LEN  # 18-byte header

    def test_oversized_fragment_fails(self):
        """Fragment data over max size should fail."""
        frag_data = b'X' * (client.MAX_FRAG_DATA_LEN + 1)
        with pytest.raises(ValueError, match='Fragment data too large'):
            client.create_fragment(0x0001, 0, 1, frag_data)

    def test_invalid_packet_id(self):
        """Invalid packet ID should fail."""
        with pytest.raises(ValueError, match='packet_id out of range'):
            client.create_fragment(0x10000000000000000, 0, 1, b'test')  # Beyond u64 max

    def test_invalid_frag_index(self):
        """Fragment index >= frag_count should fail."""
        with pytest.raises(ValueError, match='Invalid frag_index'):
            client.create_fragment(0x0001, 3, 3, b'test')


class TestKeyValueFragments:
    """Test key-value fragment creation and handling."""

    def test_fragment_with_key_len(self):
        """Test fragment creation with key_len parameter."""
        packet_id = 0x5678
        frag_index = 0
        frag_count = 1
        frag_data = b"key=value"
        key_len = 3  # First 3 bytes are the key

        fragment = client.create_fragment(packet_id, frag_index, frag_count, frag_data, key_len)

        # Verify header (18 bytes: u64 + u32 + u32 + u8 + u8)
        assert len(fragment) == 27  # 18 byte header + 9 byte data
        pid, fidx, fcnt, flen, klen = struct.unpack('!QIIBB', fragment[:18])
        assert pid == 0x5678
        assert fidx == 0
        assert fcnt == 1
        assert flen == 9
        assert klen == 3
        assert fragment[18:] == b"key=value"

    def test_key_len_max_value(self):
        """Test key_len with maximum u8 value (255)."""
        frag_data = b'X' * client.MAX_FRAG_DATA_LEN
        fragment = client.create_fragment(0x0001, 0, 1, frag_data, key_len=255)

        # Verify key_len in header
        klen = struct.unpack('B', fragment[17:18])[0]
        assert klen == 255

    def test_key_len_out_of_range(self):
        """Test that key_len > 255 fails."""
        with pytest.raises(ValueError, match='key_len out of u8 range'):
            client.create_fragment(0x0001, 0, 1, b'test', key_len=256)


class TestEncryption:
    """Test SealedBox encryption/decryption."""

    def test_encrypt_decrypt_round_trip(self):
        """Encryption and decryption should be inverses."""
        # Generate keypair
        server_privkey = nacl.public.PrivateKey.generate()
        server_pubkey = server_privkey.public_key

        plaintext = b"test data"

        # Encrypt (client-side)
        ciphertext = client.encrypt_fragment(plaintext, server_pubkey)

        # Decrypt (server-side)
        sealedbox = nacl.public.SealedBox(server_privkey)
        decrypted = sealedbox.decrypt(ciphertext)

        assert plaintext == decrypted

    def test_encryption_overhead(self):
        """SealedBox should add 48 bytes overhead."""
        server_privkey = nacl.public.PrivateKey.generate()
        server_pubkey = server_privkey.public_key

        plaintext = b"test"
        ciphertext = client.encrypt_fragment(plaintext, server_pubkey)

        assert len(ciphertext) == len(plaintext) + 48

    def test_encryption_is_nondeterministic(self):
        """SealedBox encryption should be nondeterministic."""
        server_privkey = nacl.public.PrivateKey.generate()
        server_pubkey = server_privkey.public_key

        plaintext = b"test"
        ciphertext1 = client.encrypt_fragment(plaintext, server_pubkey)
        ciphertext2 = client.encrypt_fragment(plaintext, server_pubkey)

        # Different ciphertexts for same plaintext
        assert ciphertext1 != ciphertext2

        # But both decrypt to same plaintext
        sealedbox = nacl.public.SealedBox(server_privkey)
        assert sealedbox.decrypt(ciphertext1) == plaintext
        assert sealedbox.decrypt(ciphertext2) == plaintext


class TestBase32Encoding:
    """Test base32 encoding."""

    def test_basic_encoding(self):
        """Test basic base32 encoding."""
        data = b"test"
        encoded = client.base32_encode(data)
        assert encoded == "orsxg5a"  # Lowercase, no padding

    def test_encoding_no_padding(self):
        """Base32 should not include padding."""
        data = b"hello"
        encoded = client.base32_encode(data)
        assert '=' not in encoded

    def test_encoding_is_lowercase(self):
        """Base32 should be lowercase."""
        data = b"HELLO WORLD"
        encoded = client.base32_encode(data)
        assert encoded == encoded.lower()
        assert encoded.isupper() is False

    def test_empty_data(self):
        """Empty data should encode to empty string."""
        encoded = client.base32_encode(b'')
        assert encoded == ''


class TestDNSLabelSplitting:
    """Test DNS label splitting."""

    def test_short_string(self):
        """Short string should be single label."""
        data = "a" * 50
        labels = client.split_to_labels(data, 63)
        assert len(labels) == 1
        assert labels[0] == data

    def test_exactly_63_chars(self):
        """Exactly 63 chars should be single label."""
        data = "a" * 63
        labels = client.split_to_labels(data, 63)
        assert len(labels) == 1
        assert len(labels[0]) == 63

    def test_64_chars(self):
        """64 chars should split into two labels."""
        data = "a" * 64
        labels = client.split_to_labels(data, 63)
        assert len(labels) == 2
        assert len(labels[0]) == 63
        assert len(labels[1]) == 1

    def test_long_string(self):
        """Long string should split correctly."""
        data = "a" * 200
        labels = client.split_to_labels(data, 63)
        assert len(labels) == 4  # 63 + 63 + 63 + 11
        assert len(labels[0]) == 63
        assert len(labels[1]) == 63
        assert len(labels[2]) == 63
        assert len(labels[3]) == 11

    def test_empty_string(self):
        """Empty string should return empty list or list with empty string."""
        labels = client.split_to_labels('', 63)
        # Empty string splits into empty list
        assert labels == []


class TestDNSQueryGeneration:
    """Test DNS query name generation."""

    def test_basic_query(self):
        """Test basic DNS query generation."""
        encrypted = b"test"
        domain = ".asd.qwe"

        dns_name = client.create_dns_query(encrypted, domain)

        # Should be base32(encrypted) + domain
        expected_b32 = client.base32_encode(encrypted)
        assert dns_name == expected_b32 + domain

    def test_long_encrypted_data(self):
        """Long encrypted data should split into labels."""
        # Create long data that will need multiple labels
        encrypted = b"X" * 100  # ~160 chars base32
        domain = ".test.com"

        dns_name = client.create_dns_query(encrypted, domain)

        # Should contain dots for label splitting
        assert dns_name.endswith(domain)
        assert '.' in dns_name[:-len(domain)]  # Has label separators

    def test_query_format(self):
        """DNS query should have proper format."""
        encrypted = b"abc"
        domain = ".example.org"

        dns_name = client.create_dns_query(encrypted, domain)

        # Should be lowercase (base32)
        assert dns_name[:-len(domain)].islower()
        # Should end with domain
        assert dns_name.endswith(domain)
        # Should be valid DNS name characters
        assert all(c.isalnum() or c == '.' for c in dns_name)


class TestDataFragmentation:
    """Test data fragmentation."""

    def test_small_data(self):
        """Small data should be single fragment."""
        data = b"Hello"
        fragments = client.fragment_data(data, 80)
        assert len(fragments) == 1
        assert fragments[0] == data

    def test_exactly_max_size(self):
        """Data exactly max size should be single fragment."""
        data = b"X" * 80
        fragments = client.fragment_data(data, 80)
        assert len(fragments) == 1
        assert fragments[0] == data

    def test_one_byte_over(self):
        """One byte over max should be two fragments."""
        data = b"X" * 81
        fragments = client.fragment_data(data, 80)
        assert len(fragments) == 2
        assert len(fragments[0]) == 80
        assert len(fragments[1]) == 1

    def test_multi_fragment(self):
        """Large data should split correctly."""
        data = b"X" * 250
        fragments = client.fragment_data(data, 80)
        assert len(fragments) == 4  # 80 + 80 + 80 + 10
        assert len(fragments[0]) == 80
        assert len(fragments[1]) == 80
        assert len(fragments[2]) == 80
        assert len(fragments[3]) == 10

    def test_empty_data(self):
        """Empty data should return one empty fragment."""
        fragments = client.fragment_data(b'', 80)
        assert len(fragments) == 1
        assert fragments[0] == b''


class TestMumbojumboClient:
    """Test the MumbojumboClient class interface."""

    def test_client_initialization(self):
        """Test client initialization."""
        server_privkey = nacl.public.PrivateKey.generate()
        server_pubkey = server_privkey.public_key

        # Initialize with bytes
        client1 = client.MumbojumboClient(server_pubkey.encode(), '.test.com')
        assert client1.domain == '.test.com'

        # Initialize with PublicKey object
        client2 = client.MumbojumboClient(server_pubkey, '.test.com')
        assert client2.domain == '.test.com'

        # Domain without dot should be auto-fixed
        client3 = client.MumbojumboClient(server_pubkey, 'test.com')
        assert client3.domain == '.test.com'

    def test_packet_id_managed_internally(self):
        """Test that packet IDs are managed internally and not exposed."""
        server_privkey = nacl.public.PrivateKey.generate()
        client_obj = client.MumbojumboClient(server_privkey.public_key, '.test.com')

        key = b"testkey"
        value = b"testvalue"

        # generate_queries_key_val should return list of strings
        queries1 = client_obj.generate_queries_key_val(key, value)
        queries2 = client_obj.generate_queries_key_val(key, value)

        # Should return list of strings
        assert isinstance(queries1, list)
        assert isinstance(queries2, list)
        assert all(isinstance(q, str) for q in queries1)
        assert all(isinstance(q, str) for q in queries2)

        # Queries should be different (different packet IDs)
        assert queries1[0] != queries2[0]


class TestEndToEndFlow:
    """Test complete end-to-end flow."""

    def test_single_fragment_message(self):
        """Test complete flow for single-fragment message."""
        # Setup
        server_privkey = nacl.public.PrivateKey.generate()
        server_pubkey = server_privkey.public_key
        message = b"Hello World"
        packet_id = 0x1234
        domain = ".test.com"

        # Fragment
        fragments = client.fragment_data(message, 80)
        assert len(fragments) == 1

        # Process fragment
        plaintext_frag = client.create_fragment(packet_id, 0, 1, fragments[0])
        encrypted = client.encrypt_fragment(plaintext_frag, server_pubkey)
        dns_name = client.create_dns_query(encrypted, domain)

        # Verify we can reconstruct
        # 1. Extract base32 part (remove domain and any label dots)
        b32_part = dns_name[:-len(domain)].replace('.', '')
        # 2. Decode base32
        # (Need to add padding back for standard decoder)
        padding_needed = (8 - len(b32_part) % 8) % 8
        b32_padded = b32_part.upper() + '=' * padding_needed
        encrypted_recovered = base64.b32decode(b32_padded)
        # 3. Decrypt
        sealedbox = nacl.public.SealedBox(server_privkey)
        plaintext_recovered = sealedbox.decrypt(encrypted_recovered)
        # 4. Parse fragment header (18 bytes: u64 + u32 + u32 + u16)
        pid, fidx, fcnt, flen = struct.unpack('!QIIH', plaintext_recovered[:18])
        data = plaintext_recovered[18:18+flen]

        # Verify
        assert pid == packet_id
        assert fidx == 0
        assert fcnt == 1
        assert data == message

    def test_multi_fragment_message(self):
        """Test complete flow for multi-fragment message."""
        # Setup
        server_privkey = nacl.public.PrivateKey.generate()
        server_pubkey = server_privkey.public_key
        message = b"A" * 200  # Will be 3 fragments at 80 bytes each
        packet_id = 0xBEEF
        domain = ".test.org"

        # Fragment
        fragments = client.fragment_data(message, 80)
        assert len(fragments) == 3

        # Process all fragments
        recovered_fragments = {}
        for frag_index, frag_data in enumerate(fragments):
            plaintext_frag = client.create_fragment(packet_id, frag_index, len(fragments), frag_data)
            encrypted = client.encrypt_fragment(plaintext_frag, server_pubkey)
            dns_name = client.create_dns_query(encrypted, domain)

            # Simulate server receiving and decrypting
            b32_part = dns_name[:-len(domain)].replace('.', '')  # Remove label separators
            padding_needed = (8 - len(b32_part) % 8) % 8
            b32_padded = b32_part.upper() + '=' * padding_needed
            encrypted_recovered = base64.b32decode(b32_padded)

            sealedbox = nacl.public.SealedBox(server_privkey)
            plaintext_recovered = sealedbox.decrypt(encrypted_recovered)

            # Parse header (18 bytes: u64 + u32 + u32 + u8 + u8)
            pid, fidx, fcnt, flen, klen = struct.unpack('!QIIBB', plaintext_recovered[:18])
            data = plaintext_recovered[18:18+flen]

            # Verify header
            assert pid == packet_id
            assert fcnt == 3
            recovered_fragments[fidx] = data

        # Reassemble
        reassembled = b''.join(recovered_fragments[i] for i in range(len(fragments)))
        assert reassembled == message


class TestKeyValueEndToEnd:
    """Test end-to-end key-value functionality."""

    def test_send_key_val_basic(self):
        """Test basic key-value sending."""
        server_privkey = nacl.public.PrivateKey.generate()
        client_obj = client.MumbojumboClient(server_privkey.public_key, '.test')

        key = b'filename.txt'
        value = b'Hello, World!'

        # Generate queries (don't actually send)
        queries = client_obj.generate_queries_key_val(key, value)
        assert len(queries) > 0

    def test_send_key_val_with_none_key(self):
        """Test sending with None key - should work (converts to empty bytes)."""
        server_privkey = nacl.public.PrivateKey.generate()
        client_obj = client.MumbojumboClient(server_privkey.public_key, '.test')

        # None key should work (converts to b'')
        queries = client_obj.generate_queries_key_val(None, b'value')
        assert len(queries) > 0

    def test_send_key_val_with_empty_key(self):
        """Test sending with empty key b'' - should work."""
        server_privkey = nacl.public.PrivateKey.generate()
        client_obj = client.MumbojumboClient(server_privkey.public_key, '.test')

        # Empty key should work
        queries = client_obj.generate_queries_key_val(b'', b'value')
        assert len(queries) > 0

    def test_send_key_val_rejects_none_value(self):
        """Value cannot be None - must raise ValueError."""
        server_privkey = nacl.public.PrivateKey.generate()
        client_obj = client.MumbojumboClient(server_privkey.public_key, '.test')

        # None value should raise ValueError
        with pytest.raises(ValueError, match='Value cannot be None'):
            client_obj.generate_queries_key_val(b'key', None)

    def test_send_key_val_rejects_empty_value(self):
        """Empty value b'' should raise ValueError."""
        server_privkey = nacl.public.PrivateKey.generate()
        client_obj = client.MumbojumboClient(server_privkey.public_key, '.test')

        # Empty value should raise ValueError
        with pytest.raises(ValueError, match='Value must be at least 1 byte'):
            client_obj.generate_queries_key_val(b'key', b'')

    def test_send_key_val_validates_key_type(self):
        """Key must be bytes or None."""
        server_privkey = nacl.public.PrivateKey.generate()
        client_obj = client.MumbojumboClient(server_privkey.public_key, '.test')

        with pytest.raises(TypeError, match='Key must be bytes or None'):
            client_obj.send_key_val('string_key', b'value')

    def test_send_key_val_validates_value_type(self):
        """Value must be bytes (not string, not None)."""
        server_privkey = nacl.public.PrivateKey.generate()
        client_obj = client.MumbojumboClient(server_privkey.public_key, '.test')

        with pytest.raises(TypeError, match='Value must be bytes'):
            client_obj.send_key_val(b'key', 'string_value')

    def test_send_key_val_validates_key_length(self):
        """Key length cannot exceed 255 bytes."""
        server_privkey = nacl.public.PrivateKey.generate()
        client_obj = client.MumbojumboClient(server_privkey.public_key, '.test')

        key_too_long = b'X' * 256
        with pytest.raises(ValueError, match='Key length cannot exceed 255'):
            client_obj.send_key_val(key_too_long, b'value')

    @pytest.mark.skip(reason="Timing out - needs investigation")
    def test_kv_round_trip_with_packet_engine(self):
        """Test key-value round trip through PacketEngine."""
        # Import mumbojumbo server components
        from mumbojumbo import PacketEngine, DnsPublicFragment

        # Set up keys
        server_privkey = nacl.public.PrivateKey.generate()

        # Client setup
        client_obj = client.MumbojumboClient(server_privkey.public_key, '.test')

        # Server setup
        pfcls_decrypt = DnsPublicFragment.bind(server_key=server_privkey)
        pe_decrypt = PacketEngine(frag_cls=pfcls_decrypt, max_frag_data_len=100)

        # Send key-value
        key = b'document.pdf'
        value = b'PDF content goes here...'
        data = key + value
        key_len = len(key)

        # Generate queries
        queries = client_obj._generate_dns_queries(data, key_len)

        # Simulate server receiving fragments
        for dns_name in queries:
            # Feed DNS name to PacketEngine (DnsPublicFragment will handle decoding)
            pe_decrypt.from_wire(dns_name)

        # Get reassembled packet
        packet = pe_decrypt.packet_outqueue.get()

        # Should be a dict with key and value
        assert isinstance(packet, dict)
        assert packet['key'] == key
        assert packet['value'] == value
        assert packet['key_len'] == key_len


class TestCLIIntegration:
    """Test CLI interface."""

    def test_help(self):
        """Help command should work."""
        result = subprocess.run(
            ['./venv/bin/python3', './clients/python/mumbojumbo-client.py', '--help'],
            capture_output=True,
            text=True
        )
        assert result.returncode == 0
        assert 'mumbojumbo' in result.stdout.lower()

    def test_missing_required_args(self):
        """Missing required args should fail."""
        result = subprocess.run(
            ['./venv/bin/python3', './clients/python/mumbojumbo-client.py'],
            capture_output=True,
            text=True
        )
        assert result.returncode != 0

    def test_stdin_input(self):
        """Should accept input from stdin with null key."""
        # Generate test key
        server_privkey = nacl.public.PrivateKey.generate()
        key_str = 'mj_cli_' + server_privkey.public_key.encode().hex()

        result = subprocess.run(
            ['./venv/bin/python3', './clients/python/mumbojumbo-client.py',
             '--client-key', key_str,
             '-d', '.test.com'],
            input=b'test',
            capture_output=True
        )
        assert result.returncode == 0
        # Should output DNS query
        assert b'.test.com' in result.stdout

    def test_file_input(self):
        """Should accept input from file (filename as key)."""
        # Generate test key
        server_privkey = nacl.public.PrivateKey.generate()
        key_str = 'mj_cli_' + server_privkey.public_key.encode().hex()

        # Create temp file
        with tempfile.NamedTemporaryFile(mode='wb', delete=False) as f:
            f.write(b'file content')
            temp_path = f.name

        try:
            result = subprocess.run(
                ['./venv/bin/python3', './clients/python/mumbojumbo-client.py',
                 '--client-key', key_str,
                 '-d', '.test.com',
                 temp_path],  # File as positional argument
                capture_output=True
            )
            assert result.returncode == 0
            assert b'.test.com' in result.stdout
        finally:
            os.unlink(temp_path)

    def test_explicit_key_value(self):
        """Should accept explicit -k and -v arguments."""
        server_privkey = nacl.public.PrivateKey.generate()
        key_str = 'mj_cli_' + server_privkey.public_key.encode().hex()

        result = subprocess.run(
            ['./venv/bin/python3', './clients/python/mumbojumbo-client.py',
             '--client-key', key_str,
             '-d', '.test.com',
             '-k', 'mykey',
             '-v', 'myvalue'],
            capture_output=True
        )
        assert result.returncode == 0
        assert b'.test.com' in result.stdout

    def test_domain_auto_dot(self):
        """Should auto-add leading dot to domain."""
        server_privkey = nacl.public.PrivateKey.generate()
        key_str = 'mj_cli_' + server_privkey.public_key.encode().hex()

        result = subprocess.run(
            ['./venv/bin/python3', './clients/python/mumbojumbo-client.py',
             '--client-key', key_str,
             '-d', 'test.com'],  # No leading dot
            input=b'test',
            capture_output=True
        )
        # Should warn about adding dot
        assert b'Warning' in result.stderr or b'.test.com' in result.stdout

    def test_stdin_with_custom_key(self):
        """Should accept -k argument with stdin input."""
        server_privkey = nacl.public.PrivateKey.generate()
        key_str = 'mj_cli_' + server_privkey.public_key.encode().hex()

        result = subprocess.run(
            ['./venv/bin/python3', './clients/python/mumbojumbo-client.py',
             '--client-key', key_str,
             '-d', '.test.com',
             '-k', 'my-custom-key'],
            input=b'test data from stdin',
            capture_output=True
        )
        assert result.returncode == 0
        assert b'.test.com' in result.stdout

    def test_file_with_key_arg_rejected(self):
        """Should reject -k argument when sending files (filename is key)."""
        server_privkey = nacl.public.PrivateKey.generate()
        key_str = 'mj_cli_' + server_privkey.public_key.encode().hex()

        # Create temp file
        with tempfile.NamedTemporaryFile(mode='wb', delete=False) as f:
            f.write(b'file content')
            temp_path = f.name

        try:
            result = subprocess.run(
                ['./venv/bin/python3', './clients/python/mumbojumbo-client.py',
                 '--client-key', key_str,
                 '-d', '.test.com',
                 '-k', 'should-be-rejected',  # This should cause error
                 temp_path],
                capture_output=True
            )
            # Should fail with error about -k not allowed with files
            assert result.returncode != 0
            assert b'Cannot use -k/--key with files' in result.stderr
        finally:
            os.unlink(temp_path)


if __name__ == '__main__':
    pytest.main([__file__, '-v'])
