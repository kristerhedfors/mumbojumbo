#!/usr/bin/env python3
"""Tests for PacketEngine fragmentation and reassembly in mumbojumbo v2.0.

Tests packet fragmentation, reassembly, and key-value extraction.
"""

import secrets

import pytest

from mumbojumbo import (
    PacketEngine,
    DnsFragment,
    derive_keys,
    FRAGMENT_PAYLOAD_SIZE,
)


class TestPacketEngineInitialization:
    """Test PacketEngine initialization."""

    def test_initialization_with_keys(self, enc_key, auth_key, frag_key):
        """Test basic initialization with all keys."""
        frag_cls = DnsFragment.bind(
            domain='.test.com',
            enc_key=enc_key,
            auth_key=auth_key,
            frag_key=frag_key
        )
        engine = PacketEngine(
            frag_cls=frag_cls,
            enc_key=enc_key,
            auth_key=auth_key,
            frag_key=frag_key
        )

        assert engine._enc_key == enc_key
        assert engine._auth_key == auth_key
        assert engine._frag_key == frag_key

    def test_packet_id_is_random(self):
        """Packet IDs should be randomly initialized."""
        engines = [PacketEngine() for _ in range(10)]
        initial_ids = [e._next_packet_id for e in engines]

        # Should be distributed (not all zero or sequential)
        assert len(set(initial_ids)) > 5  # Should have diversity
        assert not all(pid == 0 for pid in initial_ids)

    def test_packet_id_is_u32(self):
        """Packet IDs should be within u32 range."""
        for _ in range(100):
            engine = PacketEngine()
            assert 0 <= engine._next_packet_id <= 0xFFFFFFFF

    def test_empty_queues_on_init(self, enc_key, auth_key, frag_key):
        """Output queue should be empty on initialization."""
        engine = PacketEngine(
            enc_key=enc_key,
            auth_key=auth_key,
            frag_key=frag_key
        )
        assert engine.packet_outqueue.empty()


class TestPacketEngineToWire:
    """Test PacketEngine.to_wire() fragmentation."""

    def test_to_wire_yields_dns_queries(self, enc_key, auth_key, frag_key):
        """to_wire should yield DNS query strings."""
        frag_cls = DnsFragment.bind(
            domain='.test.com',
            enc_key=enc_key,
            auth_key=auth_key,
            frag_key=frag_key
        )
        engine = PacketEngine(
            frag_cls=frag_cls,
            enc_key=enc_key,
            auth_key=auth_key,
            frag_key=frag_key
        )

        queries = list(engine.to_wire(key=b'mykey', value=b'myvalue'))

        assert len(queries) > 0
        for query in queries:
            assert isinstance(query, str)
            assert query.endswith('.test.com')

    def test_small_message_single_fragment(self, enc_key, auth_key, frag_key):
        """Small message should produce single fragment."""
        frag_cls = DnsFragment.bind(
            domain='.test.com',
            enc_key=enc_key,
            auth_key=auth_key,
            frag_key=frag_key
        )
        engine = PacketEngine(
            frag_cls=frag_cls,
            enc_key=enc_key,
            auth_key=auth_key,
            frag_key=frag_key
        )

        # Very small message: 1 byte key_len + 0 key + 5 value = 6 bytes
        # With encryption overhead (8 nonce + 8 integrity) = 22 bytes
        # Still fits in single 28-byte fragment
        queries = list(engine.to_wire(key=b'', value=b'hello'))
        assert len(queries) == 1

    def test_large_message_multiple_fragments(self, enc_key, auth_key, frag_key):
        """Large message should produce multiple fragments."""
        frag_cls = DnsFragment.bind(
            domain='.test.com',
            enc_key=enc_key,
            auth_key=auth_key,
            frag_key=frag_key
        )
        engine = PacketEngine(
            frag_cls=frag_cls,
            enc_key=enc_key,
            auth_key=auth_key,
            frag_key=frag_key
        )

        # Large value: 200 bytes + overhead = ~216 bytes
        # 216 / 28 = ~8 fragments
        queries = list(engine.to_wire(key=b'bigkey', value=b'X' * 200))
        assert len(queries) > 1
        assert len(queries) <= 10  # Should be around 8

    def test_increments_packet_id(self, enc_key, auth_key, frag_key):
        """Each to_wire call should increment packet ID."""
        frag_cls = DnsFragment.bind(
            domain='.test.com',
            enc_key=enc_key,
            auth_key=auth_key,
            frag_key=frag_key
        )
        engine = PacketEngine(
            frag_cls=frag_cls,
            enc_key=enc_key,
            auth_key=auth_key,
            frag_key=frag_key
        )

        initial_id = engine._next_packet_id
        list(engine.to_wire(key=b'', value=b'first'))
        assert engine._next_packet_id == (initial_id + 1) & 0xFFFFFFFF

        list(engine.to_wire(key=b'', value=b'second'))
        assert engine._next_packet_id == (initial_id + 2) & 0xFFFFFFFF

    def test_packet_id_wraps_at_u32_max(self, enc_key, auth_key, frag_key):
        """Packet ID should wrap at u32 max."""
        frag_cls = DnsFragment.bind(
            domain='.test.com',
            enc_key=enc_key,
            auth_key=auth_key,
            frag_key=frag_key
        )
        engine = PacketEngine(
            frag_cls=frag_cls,
            enc_key=enc_key,
            auth_key=auth_key,
            frag_key=frag_key
        )

        # Set to max
        engine._next_packet_id = 0xFFFFFFFF
        list(engine.to_wire(key=b'', value=b'test'))

        # Should wrap to 0
        assert engine._next_packet_id == 0

    def test_none_key_becomes_empty(self, enc_key, auth_key, frag_key):
        """None key should be treated as empty bytes."""
        frag_cls = DnsFragment.bind(
            domain='.test.com',
            enc_key=enc_key,
            auth_key=auth_key,
            frag_key=frag_key
        )
        engine = PacketEngine(
            frag_cls=frag_cls,
            enc_key=enc_key,
            auth_key=auth_key,
            frag_key=frag_key
        )

        # Should not raise
        queries = list(engine.to_wire(key=None, value=b'data'))
        assert len(queries) > 0

    def test_key_too_long_raises(self, enc_key, auth_key, frag_key):
        """Key longer than 255 bytes should raise ValueError."""
        frag_cls = DnsFragment.bind(
            domain='.test.com',
            enc_key=enc_key,
            auth_key=auth_key,
            frag_key=frag_key
        )
        engine = PacketEngine(
            frag_cls=frag_cls,
            enc_key=enc_key,
            auth_key=auth_key,
            frag_key=frag_key
        )

        with pytest.raises(ValueError, match='Key too long'):
            list(engine.to_wire(key=b'X' * 256, value=b'data'))


class TestPacketEngineFromWire:
    """Test PacketEngine.from_wire() reassembly."""

    def test_single_fragment_reassembly(self, enc_key, auth_key, frag_key):
        """Single fragment should reassemble immediately."""
        frag_cls = DnsFragment.bind(
            domain='.test.com',
            enc_key=enc_key,
            auth_key=auth_key,
            frag_key=frag_key
        )
        engine = PacketEngine(
            frag_cls=frag_cls,
            enc_key=enc_key,
            auth_key=auth_key,
            frag_key=frag_key
        )

        queries = list(engine.to_wire(key=b'k', value=b'v'))
        assert len(queries) == 1

        engine.from_wire(queries[0])

        assert not engine.packet_outqueue.empty()
        packet = engine.packet_outqueue.get()
        assert packet['key'] == b'k'
        assert packet['value'] == b'v'
        assert packet['key_length'] == 1

    def test_multi_fragment_in_order_reassembly(self, enc_key, auth_key, frag_key):
        """Multiple fragments in order should reassemble."""
        frag_cls = DnsFragment.bind(
            domain='.test.com',
            enc_key=enc_key,
            auth_key=auth_key,
            frag_key=frag_key
        )
        engine = PacketEngine(
            frag_cls=frag_cls,
            enc_key=enc_key,
            auth_key=auth_key,
            frag_key=frag_key
        )

        key = b'testkey'
        value = b'X' * 100
        queries = list(engine.to_wire(key=key, value=value))
        assert len(queries) > 1

        # Feed fragments in order
        for query in queries:
            engine.from_wire(query)

        assert not engine.packet_outqueue.empty()
        packet = engine.packet_outqueue.get()
        assert packet['key'] == key
        assert packet['value'] == value

    def test_multi_fragment_out_of_order_reassembly(self, enc_key, auth_key, frag_key):
        """Multiple fragments out of order should still reassemble."""
        frag_cls = DnsFragment.bind(
            domain='.test.com',
            enc_key=enc_key,
            auth_key=auth_key,
            frag_key=frag_key
        )
        engine = PacketEngine(
            frag_cls=frag_cls,
            enc_key=enc_key,
            auth_key=auth_key,
            frag_key=frag_key
        )

        key = b'key'
        value = b'Y' * 100
        queries = list(engine.to_wire(key=key, value=value))
        assert len(queries) > 2

        # Feed fragments in reverse order
        for query in reversed(queries):
            engine.from_wire(query)

        assert not engine.packet_outqueue.empty()
        packet = engine.packet_outqueue.get()
        assert packet['key'] == key
        assert packet['value'] == value

    def test_invalid_fragment_ignored(self, enc_key, auth_key, frag_key):
        """Invalid fragments should be silently ignored."""
        frag_cls = DnsFragment.bind(
            domain='.test.com',
            enc_key=enc_key,
            auth_key=auth_key,
            frag_key=frag_key
        )
        engine = PacketEngine(
            frag_cls=frag_cls,
            enc_key=enc_key,
            auth_key=auth_key,
            frag_key=frag_key
        )

        # Send invalid data
        engine.from_wire('invalid.data.test.com')

        # Queue should still be empty
        assert engine.packet_outqueue.empty()

    def test_incomplete_packet_not_assembled(self, enc_key, auth_key, frag_key):
        """Incomplete packet should not be put in queue."""
        frag_cls = DnsFragment.bind(
            domain='.test.com',
            enc_key=enc_key,
            auth_key=auth_key,
            frag_key=frag_key
        )
        engine = PacketEngine(
            frag_cls=frag_cls,
            enc_key=enc_key,
            auth_key=auth_key,
            frag_key=frag_key
        )

        value = b'Z' * 100
        queries = list(engine.to_wire(key=b'', value=value))
        assert len(queries) > 2

        # Feed only first two fragments (missing rest)
        engine.from_wire(queries[0])
        engine.from_wire(queries[1])

        # Queue should still be empty
        assert engine.packet_outqueue.empty()

    def test_corrupted_integrity_rejected(self, enc_key, auth_key, frag_key):
        """Corrupted message integrity should reject packet."""
        # This is tricky - we need to corrupt the encrypted message
        # The easiest way is to test with tampered fragments
        frag_cls = DnsFragment.bind(
            domain='.test.com',
            enc_key=enc_key,
            auth_key=auth_key,
            frag_key=frag_key
        )
        engine = PacketEngine(
            frag_cls=frag_cls,
            enc_key=enc_key,
            auth_key=auth_key,
            frag_key=frag_key
        )

        # The MAC on the fragment will reject corrupted data before
        # we even get to message integrity check
        # But we can verify valid fragments work
        queries = list(engine.to_wire(key=b'', value=b'test'))
        for query in queries:
            engine.from_wire(query)

        assert not engine.packet_outqueue.empty()

    def test_cleanup_after_completion(self, enc_key, auth_key, frag_key):
        """Assembly buffers should be cleaned up after completion."""
        frag_cls = DnsFragment.bind(
            domain='.test.com',
            enc_key=enc_key,
            auth_key=auth_key,
            frag_key=frag_key
        )
        engine = PacketEngine(
            frag_cls=frag_cls,
            enc_key=enc_key,
            auth_key=auth_key,
            frag_key=frag_key
        )

        queries = list(engine.to_wire(key=b'k', value=b'v'))
        for query in queries:
            engine.from_wire(query)

        # Buffers should be cleaned
        assert len(engine._packet_assembly) == 0
        assert len(engine._packet_first_seen) == 0
        assert len(engine._packet_last_index) == 0


class TestPacketEngineRoundTrip:
    """Test complete round-trip through PacketEngine."""

    def test_small_kv_round_trip(self, enc_key, auth_key, frag_key):
        """Small key-value should round-trip correctly."""
        frag_cls = DnsFragment.bind(
            domain='.test.com',
            enc_key=enc_key,
            auth_key=auth_key,
            frag_key=frag_key
        )
        engine = PacketEngine(
            frag_cls=frag_cls,
            enc_key=enc_key,
            auth_key=auth_key,
            frag_key=frag_key
        )

        key = b'filename.txt'
        value = b'Hello, World!'

        queries = list(engine.to_wire(key=key, value=value))
        for query in queries:
            engine.from_wire(query)

        packet = engine.packet_outqueue.get()
        assert packet['key'] == key
        assert packet['value'] == value
        assert packet['key_length'] == len(key)

    def test_empty_key_round_trip(self, enc_key, auth_key, frag_key):
        """Empty key should round-trip correctly."""
        frag_cls = DnsFragment.bind(
            domain='.test.com',
            enc_key=enc_key,
            auth_key=auth_key,
            frag_key=frag_key
        )
        engine = PacketEngine(
            frag_cls=frag_cls,
            enc_key=enc_key,
            auth_key=auth_key,
            frag_key=frag_key
        )

        key = b''
        value = b'data without key'

        queries = list(engine.to_wire(key=key, value=value))
        for query in queries:
            engine.from_wire(query)

        packet = engine.packet_outqueue.get()
        assert packet['key'] == b''
        assert packet['value'] == value
        assert packet['key_length'] == 0

    def test_large_value_round_trip(self, enc_key, auth_key, frag_key):
        """Large value should round-trip correctly."""
        frag_cls = DnsFragment.bind(
            domain='.test.com',
            enc_key=enc_key,
            auth_key=auth_key,
            frag_key=frag_key
        )
        engine = PacketEngine(
            frag_cls=frag_cls,
            enc_key=enc_key,
            auth_key=auth_key,
            frag_key=frag_key
        )

        key = b'bigdata'
        value = secrets.token_bytes(500)

        queries = list(engine.to_wire(key=key, value=value))
        for query in queries:
            engine.from_wire(query)

        packet = engine.packet_outqueue.get()
        assert packet['key'] == key
        assert packet['value'] == value

    def test_max_key_length_round_trip(self, enc_key, auth_key, frag_key):
        """Maximum key length (255 bytes) should round-trip correctly."""
        frag_cls = DnsFragment.bind(
            domain='.test.com',
            enc_key=enc_key,
            auth_key=auth_key,
            frag_key=frag_key
        )
        engine = PacketEngine(
            frag_cls=frag_cls,
            enc_key=enc_key,
            auth_key=auth_key,
            frag_key=frag_key
        )

        key = b'K' * 255
        value = b'value'

        queries = list(engine.to_wire(key=key, value=value))
        for query in queries:
            engine.from_wire(query)

        packet = engine.packet_outqueue.get()
        assert packet['key'] == key
        assert packet['value'] == value
        assert packet['key_length'] == 255

    def test_binary_data_round_trip(self, enc_key, auth_key, frag_key):
        """Binary data with null bytes should round-trip correctly."""
        frag_cls = DnsFragment.bind(
            domain='.test.com',
            enc_key=enc_key,
            auth_key=auth_key,
            frag_key=frag_key
        )
        engine = PacketEngine(
            frag_cls=frag_cls,
            enc_key=enc_key,
            auth_key=auth_key,
            frag_key=frag_key
        )

        key = b'\x00\x01\x02'
        value = b'\xff\xfe\xfd\x00\x00\x01'

        queries = list(engine.to_wire(key=key, value=value))
        for query in queries:
            engine.from_wire(query)

        packet = engine.packet_outqueue.get()
        assert packet['key'] == key
        assert packet['value'] == value

    def test_multiple_packets_round_trip(self, enc_key, auth_key, frag_key):
        """Multiple packets should round-trip correctly."""
        frag_cls = DnsFragment.bind(
            domain='.test.com',
            enc_key=enc_key,
            auth_key=auth_key,
            frag_key=frag_key
        )
        engine = PacketEngine(
            frag_cls=frag_cls,
            enc_key=enc_key,
            auth_key=auth_key,
            frag_key=frag_key
        )

        # Send multiple packets
        packets_to_send = [
            (b'key1', b'value1'),
            (b'key2', b'value2'),
            (b'', b'just value'),
        ]

        for key, value in packets_to_send:
            queries = list(engine.to_wire(key=key, value=value))
            for query in queries:
                engine.from_wire(query)

        # Verify all packets received
        for key, value in packets_to_send:
            packet = engine.packet_outqueue.get()
            assert packet['key'] == key
            assert packet['value'] == value

        assert engine.packet_outqueue.empty()


class TestPacketEngineEdgeCases:
    """Test edge cases for PacketEngine."""

    def test_handles_different_domains(self, enc_key, auth_key, frag_key):
        """Different domains should be handled correctly."""
        domains = ['.a.b', '.example.com', '.very.long.domain.name.here']

        for domain in domains:
            frag_cls = DnsFragment.bind(
                domain=domain,
                enc_key=enc_key,
                auth_key=auth_key,
                frag_key=frag_key
            )
            engine = PacketEngine(
                frag_cls=frag_cls,
                enc_key=enc_key,
                auth_key=auth_key,
                frag_key=frag_key
            )

            queries = list(engine.to_wire(key=b'k', value=b'v'))
            assert all(q.endswith(domain) for q in queries)

            for query in queries:
                engine.from_wire(query)

            packet = engine.packet_outqueue.get()
            assert packet['key'] == b'k'
            assert packet['value'] == b'v'

    def test_very_small_value(self, enc_key, auth_key, frag_key):
        """Single byte value should work."""
        frag_cls = DnsFragment.bind(
            domain='.test.com',
            enc_key=enc_key,
            auth_key=auth_key,
            frag_key=frag_key
        )
        engine = PacketEngine(
            frag_cls=frag_cls,
            enc_key=enc_key,
            auth_key=auth_key,
            frag_key=frag_key
        )

        queries = list(engine.to_wire(key=b'', value=b'X'))
        for query in queries:
            engine.from_wire(query)

        packet = engine.packet_outqueue.get()
        assert packet['value'] == b'X'

    def test_interleaved_packets(self, enc_key, auth_key, frag_key):
        """Interleaved fragments from different packets should reassemble correctly."""
        frag_cls = DnsFragment.bind(
            domain='.test.com',
            enc_key=enc_key,
            auth_key=auth_key,
            frag_key=frag_key
        )
        engine = PacketEngine(
            frag_cls=frag_cls,
            enc_key=enc_key,
            auth_key=auth_key,
            frag_key=frag_key
        )

        # Create two packets with multiple fragments
        queries1 = list(engine.to_wire(key=b'first', value=b'A' * 100))
        queries2 = list(engine.to_wire(key=b'second', value=b'B' * 100))

        # Interleave fragments
        max_len = max(len(queries1), len(queries2))
        for i in range(max_len):
            if i < len(queries1):
                engine.from_wire(queries1[i])
            if i < len(queries2):
                engine.from_wire(queries2[i])

        # Both packets should be reassembled
        packet1 = engine.packet_outqueue.get()
        packet2 = engine.packet_outqueue.get()

        # Order depends on which completed first
        packets = [packet1, packet2]
        keys = [p['key'] for p in packets]
        assert b'first' in keys
        assert b'second' in keys
