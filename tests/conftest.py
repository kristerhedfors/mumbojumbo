#!/usr/bin/env python3
"""pytest configuration and shared fixtures."""

import logging
import os
import random

import pytest
import nacl.public

# Configure logging for tests
logging.basicConfig(level=logging.INFO)


@pytest.fixture
def keypair():
    """Generate a NaCl keypair for testing."""
    private_key = nacl.public.PrivateKey.generate()
    return private_key


@pytest.fixture
def server_keypair():
    """Generate a server NaCl keypair for testing (alias for clarity)."""
    return nacl.public.PrivateKey.generate()


@pytest.fixture
def random_data():
    """Generate random test data."""
    return nacl.public.random(100)


@pytest.fixture
def serialize_deserialize():
    """
    Fixture for testing serialize/deserialize round trips.

    Returns a function that tests serialization and deserialization
    of fragment classes.
    """
    def _serialize_deserialize(frag_cls, frag_index, frag_count, frag_data):
        """Test deserialize(serialize()) of frag_cls."""
        fr1 = frag_cls(frag_index=frag_index, frag_count=frag_count,
                       frag_data=frag_data)
        fr2 = fr1.deserialize(fr1.serialize())
        assert fr1._packet_id == fr2._packet_id
        assert frag_index == fr1._frag_index == fr2._frag_index
        assert frag_count == fr1._frag_count == fr2._frag_count
        assert frag_data == fr1.frag_data == fr2.frag_data
    return _serialize_deserialize


@pytest.fixture
def multi_serialize_deserialize(serialize_deserialize):
    """
    Fixture for testing serialize/deserialize with multiple data sizes.

    Tests with:
    - zero-length data
    - one byte length data
    - 100 random data lengths between 0 and 255 (u8 constraint)
    """
    def _multi_serialize_deserialize(frag_cls):
        """Test deserialize(serialize()) with various data sizes."""
        frag_index = random.randint(0, 100)
        frag_count = random.randint(frag_index + 1, frag_index + 100)
        datalist = [b'']
        datalist += [b'a']
        # Fragment data limited to 255 bytes max (u8 data_len constraint)
        datalist += [os.urandom(random.randint(0, 255)) for i in range(100)]
        for data in datalist:
            serialize_deserialize(frag_cls, frag_index, frag_count, data)
    return _multi_serialize_deserialize


@pytest.fixture
def public_serialize_deserialize():
    """
    Fixture for testing encrypted fragment serialize/deserialize.

    Returns a function that tests serialization and deserialization
    of encrypted fragment classes (with different classes for encrypt/decrypt).
    """
    def _public_serialize_deserialize(pfcls1, pfcls2, frag_index,
                                      frag_count, frag_data):
        """Test deserialize(serialize()) of encrypted fragment classes."""
        fr1 = pfcls1(frag_index=frag_index, frag_count=frag_count,
                     frag_data=frag_data)
        fr2 = pfcls2().deserialize(fr1.serialize())
        assert fr1._packet_id == fr2._packet_id
        assert frag_index == fr1._frag_index == fr2._frag_index
        assert frag_count == fr1._frag_count == fr2._frag_count
        assert frag_data == fr1.frag_data == fr2.frag_data
    return _public_serialize_deserialize


@pytest.fixture
def multi_public_serialize_deserialize(public_serialize_deserialize):
    """
    Fixture for testing encrypted fragments with multiple data sizes.

    Tests with:
    - zero-length data
    - one byte length data
    - 100 random data lengths between 0 and 255 (u8 constraint)
    """
    def _multi_public_serialize_deserialize(pfcls1, pfcls2):
        """Test encrypted deserialize(serialize()) with various data sizes."""
        frag_index = random.randint(0, 100)
        frag_count = random.randint(frag_index + 1, frag_index + 100)
        datalist = [b'']
        datalist += [b'a']
        # Fragment data limited to 255 bytes max (u8 data_len constraint)
        datalist += [nacl.public.random(random.randint(0, 255))
                     for i in range(100)]
        for data in datalist:
            public_serialize_deserialize(pfcls1, pfcls2, frag_index,
                                        frag_count, data)
    return _multi_public_serialize_deserialize
