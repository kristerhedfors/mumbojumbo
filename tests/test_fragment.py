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
