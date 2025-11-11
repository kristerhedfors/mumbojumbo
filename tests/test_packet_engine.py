#!/usr/bin/env python3
"""Tests for PacketEngine and PublicFragment encryption."""

import random

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
        # Client encrypts with public_key, server decrypts with private_key
        server_privkey = nacl.public.PrivateKey.generate()
        pfcls_encrypt = cls.bind(public_key=server_privkey.public_key, **kw)
        pfcls_decrypt = cls.bind(private_key=server_privkey, **kw)
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
        pfcls_encrypt = DnsPublicFragment.bind(public_key=server_privkey.public_key)
        pfcls_decrypt = DnsPublicFragment.bind(private_key=server_privkey)

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
