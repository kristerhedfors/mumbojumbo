#!/usr/bin/env python3
"""Tests for basic Fragment serialization/deserialization."""

from mumbojumbo import Fragment


class TestFragment:
    """Test basic fragment serialization/deserialization."""

    def test_basic_round_trip(self):
        """Test basic fragment serialize/deserialize round trip."""
        frag_index = 4
        frag_count = 7
        frag_data = b'foobar'

        fr1 = Fragment(frag_index=frag_index, frag_count=frag_count,
                       frag_data=frag_data)
        fr2 = fr1.deserialize(fr1.serialize())

        assert fr1._packet_id == fr2._packet_id
        assert frag_index == fr1._frag_index == fr2._frag_index
        assert frag_count == fr1._frag_count == fr2._frag_count
        assert frag_data == fr1.frag_data == fr2.frag_data

    def test_round_trip_with_key_len(self):
        """Test fragment round trip with key_len parameter."""
        frag_index = 2
        frag_count = 5
        frag_data = b'key:value'
        key_len = 3

        fr1 = Fragment(frag_index=frag_index, frag_count=frag_count,
                       frag_data=frag_data, key_len=key_len)
        fr2 = fr1.deserialize(fr1.serialize())

        assert fr1._packet_id == fr2._packet_id
        assert frag_index == fr1._frag_index == fr2._frag_index
        assert frag_count == fr1._frag_count == fr2._frag_count
        assert frag_data == fr1.frag_data == fr2.frag_data
        assert key_len == fr1._key_len == fr2._key_len
