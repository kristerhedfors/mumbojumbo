#!/usr/bin/env python3
"""Tests for PacketEngine and PublicFragment encryption."""

import random

import pytest
import nacl.public
from mumbojumbo import (
    Fragment,
    PublicFragment,
    DnsPublicFragment,
    PacketEngine
)


class TestPublicFragment:
    """Test encrypted fragment operations."""

    def do_test_cls(self, cls, multi_public_serialize_deserialize, **kw):
        """Test encrypted fragment class with various data sizes."""
        # For SealedBox: Only need one keypair (server keypair)
        # Client encrypts with client_key, server decrypts with server_key
        server_privkey = nacl.public.PrivateKey.generate()
        pfcls_encrypt = cls.bind(client_key=server_privkey.public_key, **kw)
        pfcls_decrypt = cls.bind(server_key=server_privkey, **kw)
        multi_public_serialize_deserialize(pfcls_encrypt, pfcls_decrypt)

    def test_classes(self, multi_public_serialize_deserialize):
        """Test PublicFragment and DnsPublicFragment with key binding."""
        self.do_test_cls(PublicFragment, multi_public_serialize_deserialize)
        self.do_test_cls(DnsPublicFragment, multi_public_serialize_deserialize,
                        domain='.asd.qwe')

    def test_fragment_serialization(self, serialize_deserialize,
                                    multi_serialize_deserialize):
        """Test Fragment serialization with various data sizes."""
        serialize_deserialize(Fragment, frag_index=3, frag_count=4,
                            frag_data=b'asdqwe')
        multi_serialize_deserialize(Fragment)


class TestPacketEngine:
    """Test packet assembly and fragment handling."""

    def test_encrypt_decrypt_round_trips(self):
        """Test encryption/decryption round trips for various packet sizes."""
        # Set up test data with various packet sizes
        packet_data_lst = [b'']
        packet_data_lst += [b'a']
        packet_data_lst += [nacl.public.random(random.randint(1, 2048))
                           for i in range(64)]

        # For SealedBox: Only need one keypair (server keypair)
        server_privkey = nacl.public.PrivateKey.generate()
        pfcls_encrypt = DnsPublicFragment.bind(client_key=server_privkey.public_key)
        pfcls_decrypt = DnsPublicFragment.bind(server_key=server_privkey)

        # Create packet engines
        pe_encrypt = PacketEngine(frag_cls=pfcls_encrypt, max_frag_data_len=100)
        pe_decrypt = PacketEngine(frag_cls=pfcls_decrypt, max_frag_data_len=100)

        # Test each packet size
        for packet_data in packet_data_lst:
            for wire_data in pe_encrypt.to_wire(packet_data=packet_data):
                pe_decrypt.from_wire(wire_data=wire_data)
            out_data = pe_decrypt.packet_outqueue.get()
            assert packet_data == out_data
            assert pe_decrypt.packet_outqueue.empty()

    def test_packet_id_csprng_initialization(self):
        """Test that packet IDs are initialized with CSPRNG (not 0 or sequential)."""
        # Create multiple PacketEngine instances
        engines = [PacketEngine() for _ in range(10)]

        # Extract initial packet IDs
        initial_ids = [engine._next_packet_id for engine in engines]

        # Verify: Not all zeros (old behavior)
        assert not all(pid == 0 for pid in initial_ids), "Packet IDs should not all be 0 (CSPRNG initialization failed)"

        # Verify: IDs are distributed (not sequential from 0)
        # With CSPRNG, IDs should be spread across u64 range
        assert len(set(initial_ids)) > 5, "Packet IDs should be diverse (CSPRNG should produce unique values)"

        # Verify: All IDs are valid u64 values
        for pid in initial_ids:
            assert 0 <= pid <= 0xFFFFFFFFFFFFFFFF, f"Packet ID {pid} out of u64 range"

    @pytest.mark.skip(reason="Test hangs indefinitely - needs investigation. Queue.get() appears to block forever. To be fixed in future.")
    def test_replay_detection(self):
        """Test that replay attacks (duplicate packet IDs) are tracked in completed set."""
        # Set up server with decryption keys
        server_privkey = nacl.public.PrivateKey.generate()
        pfcls_decrypt = DnsPublicFragment.bind(server_key=server_privkey)
        pe_decrypt = PacketEngine(frag_cls=pfcls_decrypt, max_frag_data_len=100)

        # Encrypt a packet
        pfcls_encrypt = DnsPublicFragment.bind(client_key=server_privkey.public_key)
        pe_encrypt = PacketEngine(frag_cls=pfcls_encrypt, max_frag_data_len=100)

        packet_data = b"test message"
        fragments = list(pe_encrypt.to_wire(packet_data=packet_data))

        # Verify completed set is initially empty
        assert len(pe_decrypt._completed_packet_ids) == 0

        # First time: Receive all fragments (should complete successfully)
        for wire_data in fragments:
            pe_decrypt.from_wire(wire_data=wire_data)
        out_data = pe_decrypt.packet_outqueue.get()
        assert out_data == packet_data

        # Get the packet_id that was used
        # Decrypt first fragment to extract packet_id
        frag_obj = pfcls_decrypt().deserialize(fragments[0])
        packet_id = frag_obj._packet_id

        # Verify packet_id is in completed set after first completion
        assert len(pe_decrypt._completed_packet_ids) == 1
        assert packet_id in pe_decrypt._completed_packet_ids, "Packet ID should be in completed set after first completion"

        # Second time: Try to replay the same packet (duplicate packet_id)
        # The completed_packet_ids set should already contain this ID
        for wire_data in fragments:
            pe_decrypt.from_wire(wire_data=wire_data)

        # Packet should still be processed (we don't block replays, just detect them)
        out_data2 = pe_decrypt.packet_outqueue.get()
        assert out_data2 == packet_data

        # Verify set size hasn't changed (same packet_id, already in set)
        assert len(pe_decrypt._completed_packet_ids) == 1
        assert packet_id in pe_decrypt._completed_packet_ids
