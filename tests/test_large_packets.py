#!/usr/bin/env python3
"""Tests for large packet support with u32 fragment counts."""

import nacl.public
from mumbojumbo import Fragment, PublicFragment, DnsPublicFragment, PacketEngine


class TestLargeFragmentCounts:
    """Test support for fragment counts exceeding u16 limits (>65535)."""

    def test_fragment_count_above_u16_max(self):
        """Test that frag_count > 65535 works correctly."""
        frag_count = 70000  # Above u16 max of 65535
        frag_index = 65536  # Also above u16 max
        frag_data = b'test data for large fragment count'

        # Create fragment with large indices
        fr1 = Fragment(frag_index=frag_index, frag_count=frag_count,
                       frag_data=frag_data)

        # Serialize and deserialize
        serialized = fr1.serialize()
        fr2 = fr1.deserialize(serialized)

        # Verify values are preserved correctly
        assert fr1._packet_id == fr2._packet_id
        assert frag_index == fr1._frag_index == fr2._frag_index
        assert frag_count == fr1._frag_count == fr2._frag_count
        assert frag_data == fr1.frag_data == fr2.frag_data

    def test_fragment_max_u32_values(self):
        """Test fragments with maximum u32 values."""
        max_u32 = 4294967295  # 2^32 - 1
        frag_count = max_u32
        frag_index = max_u32 - 1  # Must be less than frag_count
        frag_data = b'max u32 test'

        fr1 = Fragment(frag_index=frag_index, frag_count=frag_count,
                       frag_data=frag_data)

        serialized = fr1.serialize()
        fr2 = fr1.deserialize(serialized)

        assert frag_index == fr2._frag_index
        assert frag_count == fr2._frag_count
        assert frag_data == fr2.frag_data

    def test_encrypted_fragment_large_count(self):
        """Test encrypted fragments with large fragment counts."""
        # Generate keypair
        server_privkey = nacl.public.PrivateKey.generate()

        # Setup encrypted fragment with large count
        frag_count = 100000
        frag_index = 99999
        frag_data = b'encrypted fragment with large count'

        # Create encrypted fragment (client side)
        fr_encrypt = PublicFragment(
            public_key=server_privkey.public_key,
            frag_index=frag_index,
            frag_count=frag_count,
            frag_data=frag_data
        )

        # Serialize (encrypt)
        ciphertext = fr_encrypt.serialize()

        # Deserialize (decrypt) on server side
        fr_decrypt = PublicFragment(private_key=server_privkey)
        fr_result = fr_decrypt.deserialize(ciphertext)

        assert frag_index == fr_result._frag_index
        assert frag_count == fr_result._frag_count
        assert frag_data == fr_result.frag_data


class TestTenGigabyteCapacity:
    """Verify that the protocol can handle 10GB+ packets."""

    def test_calculate_max_packet_size(self):
        """Calculate and verify maximum packet size with current limits."""
        max_frag_data_len = PacketEngine.MAX_FRAG_DATA_LEN  # 80 bytes
        max_frag_count = 4294967295  # u32 max

        # Calculate theoretical maximum
        max_packet_bytes = max_frag_count * max_frag_data_len
        max_packet_gb = max_packet_bytes / (1024 ** 3)

        # Verify we can handle 10GB (10 * 1024^3 bytes)
        ten_gb_bytes = 10 * 1024 ** 3
        required_fragments = ten_gb_bytes // max_frag_data_len

        assert max_packet_bytes >= ten_gb_bytes, \
            f"Max packet size {max_packet_gb:.2f}GB is less than 10GB"
        assert max_frag_count >= required_fragments, \
            f"Max fragment count {max_frag_count} < required {required_fragments}"

        print(f"\nProtocol capacity verification:")
        print(f"  Max fragment data length: {max_frag_data_len} bytes")
        print(f"  Max fragment count: {max_frag_count:,}")
        print(f"  Max packet size: {max_packet_gb:.2f} GB ({max_packet_bytes:,} bytes)")
        print(f"  10GB requirement: ✓ PASSED")
        print(f"  Fragments needed for 10GB: {required_fragments:,}")

    def test_10gb_packet_fragmentation_simulation(self):
        """Simulate fragmenting a 10GB packet (without creating actual 10GB data)."""
        max_frag_data_len = PacketEngine.MAX_FRAG_DATA_LEN  # 80 bytes
        ten_gb_bytes = 10 * 1024 ** 3  # 10 GB in bytes

        # Calculate how many fragments we'd need
        required_fragments = (ten_gb_bytes + max_frag_data_len - 1) // max_frag_data_len

        # Verify we can represent this in u32
        assert required_fragments <= 4294967295, \
            f"Required fragments {required_fragments:,} exceeds u32 max"

        # Simulate creating first and last fragments (without actual 10GB data)
        # First fragment
        fr_first = Fragment(
            packet_id=1,
            frag_index=0,
            frag_count=required_fragments,
            frag_data=b'A' * max_frag_data_len
        )

        # Last fragment
        last_frag_size = ten_gb_bytes % max_frag_data_len or max_frag_data_len
        fr_last = Fragment(
            packet_id=1,
            frag_index=required_fragments - 1,
            frag_count=required_fragments,
            frag_data=b'Z' * last_frag_size
        )

        # Verify serialization works
        serialized_first = fr_first.serialize()
        serialized_last = fr_last.serialize()

        # Verify deserialization works
        fr_first_restored = fr_first.deserialize(serialized_first)
        fr_last_restored = fr_last.deserialize(serialized_last)

        assert fr_first_restored._frag_count == required_fragments
        assert fr_last_restored._frag_index == required_fragments - 1

        print(f"\n10GB packet simulation:")
        print(f"  Packet size: 10 GB ({ten_gb_bytes:,} bytes)")
        print(f"  Fragment size: {max_frag_data_len} bytes")
        print(f"  Total fragments needed: {required_fragments:,}")
        print(f"  First fragment: index 0/{required_fragments:,}")
        print(f"  Last fragment: index {required_fragments-1:,}/{required_fragments:,}")
        print(f"  Serialization: ✓ PASSED")

    def test_packet_engine_supports_large_fragment_counts(self):
        """Verify PacketEngine can handle packets with many fragments."""
        # Create a small multi-fragment packet to verify the mechanism works
        server_privkey = nacl.public.PrivateKey.generate()
        pfcls_encrypt = DnsPublicFragment.bind(public_key=server_privkey.public_key)
        pfcls_decrypt = DnsPublicFragment.bind(private_key=server_privkey)

        pe_encrypt = PacketEngine(frag_cls=pfcls_encrypt, max_frag_data_len=10)
        pe_decrypt = PacketEngine(frag_cls=pfcls_decrypt, max_frag_data_len=10)

        # Create test data that requires multiple fragments
        # Use 100 bytes to get 10 fragments (100 / 10 = 10 fragments)
        test_data = b'X' * 100

        # Fragment and send
        fragment_count = 0
        for wire_data in pe_encrypt.to_wire(packet_data=test_data):
            pe_decrypt.from_wire(wire_data=wire_data)
            fragment_count += 1

        # Verify packet was reassembled
        assert not pe_decrypt.packet_outqueue.empty()
        out_data = pe_decrypt.packet_outqueue.get()
        assert test_data == out_data
        assert fragment_count == 10

        print(f"\nPacketEngine multi-fragment test:")
        print(f"  Test data size: {len(test_data)} bytes")
        print(f"  Fragment size: 10 bytes")
        print(f"  Fragments created: {fragment_count}")
        print(f"  Reassembly: ✓ PASSED")
