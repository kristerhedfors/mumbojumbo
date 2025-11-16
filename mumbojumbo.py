#!/usr/bin/env python3
"""
Mumbojumbo DNS Tunneling Protocol v2.0

A lightweight DNS tunneling system using ChaCha20-Poly1305 encryption.
Transmits key-value pairs over DNS queries with dual-layer authentication.

Protocol: 40-byte binary packets (base36 encoded) → single DNS label
Encryption: ChaCha20-Poly1305 with 8-byte nonce
Authentication: Fragment-level (4-byte MAC) + Message-level (8-byte MAC)

For educational and authorized security testing only.
"""

import base64
import functools
import logging
import logging.handlers
import os
import queue
import secrets
import socket
import struct
import subprocess
import sys
import optparse
import configparser
import traceback
import smtplib
import hashlib
import hmac
import getpass
import json
import datetime
import signal
import time
from email.mime.text import MIMEText


# ============================================================================
# Cryptography Implementations (ChaCha20, Poly1305, Base36)
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
    """Generate a 64-byte ChaCha20 keystream block."""
    constants = [0x61707865, 0x3320646e, 0x79622d32, 0x6b206574]
    key_words = list(struct.unpack('<8I', key))
    counter_word = counter & 0xffffffff
    nonce_words = list(struct.unpack('<3I', nonce))

    state = constants + key_words + [counter_word] + nonce_words
    working_state = state[:]

    for _ in range(10):
        quarter_round(working_state, 0, 4, 8, 12)
        quarter_round(working_state, 1, 5, 9, 13)
        quarter_round(working_state, 2, 6, 10, 14)
        quarter_round(working_state, 3, 7, 11, 15)
        quarter_round(working_state, 0, 5, 10, 15)
        quarter_round(working_state, 1, 6, 11, 12)
        quarter_round(working_state, 2, 7, 8, 13)
        quarter_round(working_state, 3, 4, 9, 14)

    for i in range(16):
        working_state[i] = (working_state[i] + state[i]) & 0xffffffff

    return struct.pack('<16I', *working_state)


def chacha20_encrypt(key, nonce, plaintext, counter=0):
    """Encrypt/decrypt with ChaCha20."""
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

    keystream = keystream[:len(plaintext)]
    return bytes(p ^ k for p, k in zip(plaintext, keystream))


chacha20_decrypt = chacha20_encrypt


def poly1305_mac(key, msg):
    """Compute Poly1305 MAC."""
    if len(key) != 32:
        raise ValueError(f"Key must be 32 bytes, got {len(key)}")

    r_bytes = key[:16]
    s_bytes = key[16:32]

    r = int.from_bytes(r_bytes, 'little')
    r &= 0x0ffffffc0ffffffc0ffffffc0fffffff
    s = int.from_bytes(s_bytes, 'little')
    p = (1 << 130) - 5

    accumulator = 0
    for i in range(0, len(msg), 16):
        block = msg[i:i+16]
        if len(block) == 16:
            n = int.from_bytes(block + b'\x01', 'little')
        else:
            n = int.from_bytes(block + b'\x01', 'little')
        accumulator = ((accumulator + n) * r) % p

    accumulator = (accumulator + s) % (1 << 128)
    return accumulator.to_bytes(16, 'little')


BASE36_ALPHABET = '0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ'


def base36_encode(data):
    """Encode bytes to base36 string (uppercase)."""
    if not data:
        return '0'
    num = int.from_bytes(data, 'big')
    if num == 0:
        return '0'
    result = []
    while num > 0:
        num, remainder = divmod(num, 36)
        result.append(BASE36_ALPHABET[remainder])
    return ''.join(reversed(result))


def base36_decode(s):
    """Decode base36 string to bytes."""
    s = s.upper().strip()
    num = 0
    for char in s:
        if char not in BASE36_ALPHABET:
            raise ValueError(f"Invalid base36 character: {char}")
        num = num * 36 + BASE36_ALPHABET.index(char)
    if num == 0:
        return b'\x00'
    byte_length = (num.bit_length() + 7) // 8
    return num.to_bytes(byte_length, 'big')


# ============================================================================
# Protocol Constants
# ============================================================================

BINARY_PACKET_SIZE = 40
BASE36_PACKET_SIZE = 63
FRAGMENT_HEADER_SIZE = 4
FRAGMENT_MAC_SIZE = 4
FRAGMENT_PAYLOAD_SIZE = 32
PACKET_ID_SIZE = 2
FRAGMENT_DATA_SIZE = 30
MESSAGE_NONCE_SIZE = 8
MESSAGE_INTEGRITY_SIZE = 8
KEY_LENGTH_SIZE = 1

FIRST_FLAG_MASK = 0x80000000
MORE_FLAG_MASK = 0x40000000
INDEX_MASK = 0x3FFFFFFF


# ============================================================================
# Global Logger
# ============================================================================

logging.basicConfig(level=logging.DEBUG)
global logger
logger = logging.getLogger(__name__)


# ============================================================================
# Protocol Classes
# ============================================================================

class MJException(Exception):
    pass


class Bindable(object):
    @classmethod
    def bind(cls, *args, **kw):
        return functools.partial(cls, *args, **kw)


class BaseFragment(Bindable):
    """Base fragment class."""
    def __init__(self, frag_data=''):
        self._frag_data = frag_data

    @property
    def frag_data(self):
        return self._frag_data

    def serialize(self):
        return self._frag_data

    def deserialize(self, raw):
        return self.__class__(frag_data=raw)


class Fragment(BaseFragment):
    """
    Transport packet fragment with new v2.0 protocol.

    Wire format (40 bytes):
        4 bytes: Fragment header (u32 bitfield: first flag, more flag, 30-bit index)
        4 bytes: Truncated Poly1305 MAC (fragment-level authentication)
        32 bytes: Fragment payload (2B packet_id + 30B fragment_data)

    Base36 encoded to 63 characters for DNS label.
    """

    def __init__(self, packet_id=None, frag_index=0, is_first=False,
                 has_more=False, frag_key=None, **kw):
        self._packet_id = packet_id if packet_id is not None else 0
        self._frag_index = frag_index
        self._is_first = is_first
        self._has_more = has_more
        self._frag_key = frag_key
        super(Fragment, self).__init__(**kw)

    def _build_header(self):
        """Build 4-byte header with flags and index."""
        flags = 0
        if self._is_first:
            flags |= FIRST_FLAG_MASK
        if self._has_more:
            flags |= MORE_FLAG_MASK
        flags |= (self._frag_index & INDEX_MASK)
        return struct.pack('!I', flags)

    def _parse_header(self, header):
        """Parse 4-byte header to extract flags and index."""
        flags = struct.unpack('!I', header)[0]
        is_first = bool(flags & FIRST_FLAG_MASK)
        has_more = bool(flags & MORE_FLAG_MASK)
        frag_index = flags & INDEX_MASK
        return is_first, has_more, frag_index

    def serialize(self):
        """
        Serialize to 40-byte binary packet.

        Returns:
            40 bytes: [header (4B)][MAC (4B)][payload (32B)]
        """
        # Build payload: [packet_id (2B)][fragment_data (30B)]
        payload = struct.pack('!H', self._packet_id)  # u16 big-endian
        payload += self._frag_data[:FRAGMENT_DATA_SIZE]

        # Pad to 32 bytes if needed
        if len(payload) < FRAGMENT_PAYLOAD_SIZE:
            payload += b'\x00' * (FRAGMENT_PAYLOAD_SIZE - len(payload))

        # Compute 4-byte fragment MAC over payload
        if self._frag_key:
            mac_full = poly1305_mac(self._frag_key, payload)
            mac = mac_full[:4]
        else:
            mac = b'\x00\x00\x00\x00'

        # Build header
        header = self._build_header()

        # Assemble packet
        packet = header + mac + payload
        assert len(packet) == BINARY_PACKET_SIZE
        return packet

    def deserialize(self, packet):
        """
        Deserialize 40-byte binary packet.

        Args:
            packet: 40 bytes

        Returns:
            Fragment instance or None if invalid
        """
        if len(packet) != BINARY_PACKET_SIZE:
            logger.debug(f'Invalid packet size: {len(packet)} (expected {BINARY_PACKET_SIZE})')
            return None

        # Parse packet
        header = packet[0:4]
        mac = packet[4:8]
        payload = packet[8:40]

        # Verify fragment MAC
        if self._frag_key:
            mac_computed = poly1305_mac(self._frag_key, payload)[:4]
            if mac != mac_computed:
                logger.debug('Fragment MAC verification failed')
                return None

        # Parse header
        is_first, has_more, frag_index = self._parse_header(header)

        # Parse payload
        packet_id = struct.unpack('!H', payload[0:2])[0]
        frag_data = payload[2:32]

        # Remove trailing zeros (no explicit length field in new protocol)
        frag_data = frag_data.rstrip(b'\x00')

        # Build keyword arguments
        kw = {
            'packet_id': packet_id,
            'frag_index': frag_index,
            'is_first': is_first,
            'has_more': has_more,
            'frag_data': frag_data,
            'frag_key': self._frag_key
        }

        return self.__class__(**kw)


class EncryptedFragment(Fragment):
    """
    Fragment with message-level ChaCha20-Poly1305 encryption.

    This class handles the encryption/decryption layer that wraps
    the complete message BEFORE fragmentation.
    """

    def __init__(self, enc_key=None, auth_key=None, **kw):
        """
        Initialize encrypted fragment.

        Args:
            enc_key: 32-byte ChaCha20 encryption key
            auth_key: 32-byte Poly1305 auth key (for message integrity)
            frag_key: 32-byte Poly1305 key (for fragment MACs, from parent)
        """
        if isinstance(enc_key, str):
            enc_key = decode_key_hex(enc_key)
        if isinstance(auth_key, str):
            auth_key = decode_key_hex(auth_key)

        self._enc_key = enc_key
        self._auth_key = auth_key
        super(EncryptedFragment, self).__init__(**kw)

    @staticmethod
    def encrypt_message(enc_key, auth_key, plaintext):
        """
        Encrypt complete message (called before fragmentation).

        Args:
            enc_key: 32-byte encryption key
            auth_key: 32-byte authentication key
            plaintext: Complete message to encrypt

        Returns:
            bytes: [nonce (8B)][integrity (8B)][encrypted_kv]
        """
        # Generate 8-byte nonce
        nonce = os.urandom(MESSAGE_NONCE_SIZE)

        # Encrypt with ChaCha20
        encrypted_kv = chacha20_encrypt(enc_key, nonce, plaintext)

        # Compute 8-byte integrity MAC
        integrity_full = poly1305_mac(auth_key, nonce + encrypted_kv)
        integrity = integrity_full[:MESSAGE_INTEGRITY_SIZE]

        # Build complete message
        message = nonce + integrity + encrypted_kv
        return message

    @staticmethod
    def decrypt_message(enc_key, auth_key, message):
        """
        Decrypt complete message (called after reassembly).

        Args:
            enc_key: 32-byte encryption key
            auth_key: 32-byte authentication key
            message: Complete encrypted message

        Returns:
            bytes: Decrypted plaintext, or None if integrity check fails
        """
        if len(message) < MESSAGE_NONCE_SIZE + MESSAGE_INTEGRITY_SIZE:
            logger.debug(f'Message too short: {len(message)} bytes')
            return None

        # Parse message
        nonce = message[0:MESSAGE_NONCE_SIZE]
        integrity = message[MESSAGE_NONCE_SIZE:MESSAGE_NONCE_SIZE + MESSAGE_INTEGRITY_SIZE]
        encrypted_kv = message[MESSAGE_NONCE_SIZE + MESSAGE_INTEGRITY_SIZE:]

        # VERIFY integrity FIRST (before decryption!)
        integrity_computed = poly1305_mac(auth_key, nonce + encrypted_kv)[:MESSAGE_INTEGRITY_SIZE]
        if integrity != integrity_computed:
            logger.error('Message integrity check FAILED - possible tampering!')
            return None

        # Decrypt (only if integrity passed)
        plaintext = chacha20_decrypt(enc_key, nonce, encrypted_kv)
        return plaintext


class DnsFragment(EncryptedFragment):
    """
    DNS-encoded fragment using base36 encoding.

    Encodes 40-byte binary packet to 63-character base36 string,
    suitable for single DNS label.
    """

    DEFAULT_DOMAIN = '.example.com'

    def __init__(self, domain=DEFAULT_DOMAIN, **kw):
        self._domain = domain
        super(DnsFragment, self).__init__(**kw)

    def serialize(self):
        """
        Serialize to DNS query string.

        Returns:
            str: <63-char-base36>.<domain>
        """
        # Get 40-byte binary packet
        binary_packet = super(DnsFragment, self).serialize()

        # Base36 encode
        base36_str = base36_encode(binary_packet)

        # Pad to 63 characters if needed (for consistent length)
        if len(base36_str) < BASE36_PACKET_SIZE:
            base36_str = '0' * (BASE36_PACKET_SIZE - len(base36_str)) + base36_str

        # Build DNS query
        dns_query = base36_str + self._domain
        return dns_query

    def deserialize(self, dns_query):
        """
        Deserialize DNS query string.

        Args:
            dns_query: str, DNS query name

        Returns:
            Fragment instance or None if invalid
        """
        logger.debug(f'DnsFragment: deserialize() {dns_query[:50]}...')

        if not dns_query.endswith(self._domain):
            logger.debug(f'Invalid domain: {dns_query[:30]}')
            return None

        # Extract base36 part
        base36_str = dns_query[:-len(self._domain)]

        # Decode base36
        try:
            binary_packet = base36_decode(base36_str)
        except Exception as e:
            logger.debug(f'Base36 decode failed: {type(e).__name__}: {e}')
            return None

        # Pad to 40 bytes if needed (leading zeros may have been lost)
        if len(binary_packet) < BINARY_PACKET_SIZE:
            binary_packet = b'\x00' * (BINARY_PACKET_SIZE - len(binary_packet)) + binary_packet

        # Deserialize binary packet
        return super(DnsFragment, self).deserialize(binary_packet)


def _split2len(s, n):
    """Split bytes into n-byte chunks."""
    assert n > 0
    if s == b'':
        return [b'']
    def _f(s, n):
        while s:
            yield s[:n]
            s = s[n:]
    return list(_f(s, n))


class PacketEngine(object):
    """
    Packet fragmentation and reassembly engine for v2.0 protocol.

    Handles:
    - Message-level encryption (single encryption before fragmentation)
    - Fragmentation into 30-byte chunks
    - Fragment-level authentication
    - Reassembly with integrity verification
    - Key-value extraction
    """

    def __init__(self, frag_cls=None, enc_key=None, auth_key=None, frag_key=None):
        """
        Initialize packet engine.

        Args:
            frag_cls: Fragment class (or bound partial)
            enc_key: 32-byte encryption key
            auth_key: 32-byte authentication key
            frag_key: 32-byte fragment MAC key
        """
        self._frag_cls = frag_cls
        self._enc_key = enc_key
        self._auth_key = auth_key
        self._frag_key = frag_key

        # Reassembly state
        self._packet_assembly = {}  # packet_id -> list of fragment_data
        self._packet_first_seen = {}  # packet_id -> bool (track first flag)
        self._packet_outqueue = queue.Queue()

        # Packet ID counter (u16: 0-65535, wraps)
        self._next_packet_id = secrets.randbits(16)

    @property
    def packet_outqueue(self):
        return self._packet_outqueue

    def to_wire(self, key, value):
        """
        Encrypt and fragment a key-value pair.

        Args:
            key: bytes, key data (or None/b'' for no key)
            value: bytes, value data

        Yields:
            DNS query strings (one per fragment)
        """
        # Build plaintext: [key_length (1B)][key_data][value_data]
        if key is None:
            key = b''
        key_length = len(key)
        if key_length > 255:
            raise ValueError(f'Key too long: {key_length} bytes (max 255)')

        plaintext = bytes([key_length]) + key + value

        # Encrypt message ONCE
        message = EncryptedFragment.encrypt_message(self._enc_key, self._auth_key, plaintext)

        logger.debug(f'Encrypted message: {len(message)} bytes')

        # Fragment into 30-byte chunks
        packet_id = self._next_packet_id
        self._next_packet_id = (self._next_packet_id + 1) & 0xFFFF  # Wrap at 2^16-1

        fragments = _split2len(message, FRAGMENT_DATA_SIZE)
        total_fragments = len(fragments)

        logger.debug(f'Fragmenting into {total_fragments} fragments (packet_id={packet_id})')

        for frag_index, frag_data in enumerate(fragments):
            is_first = (frag_index == 0)
            has_more = (frag_index < total_fragments - 1)

            frag = self._frag_cls(
                packet_id=packet_id,
                frag_index=frag_index,
                is_first=is_first,
                has_more=has_more,
                frag_data=frag_data,
                enc_key=self._enc_key,
                auth_key=self._auth_key,
                frag_key=self._frag_key
            )

            wire_data = frag.serialize()
            yield wire_data

    def from_wire(self, wire_data):
        """
        Receive and reassemble fragments.

        If fragment completes a message, verify integrity, decrypt,
        and put (key, value) to packet_outqueue.

        Args:
            wire_data: DNS query string or binary packet
        """
        logger.debug(f'from_wire() len(wire_data)={len(wire_data)}')

        # Deserialize fragment
        frag = self._frag_cls().deserialize(wire_data)
        if frag is None:
            logger.debug('Fragment deserialization failed')
            return

        packet_id = frag._packet_id
        frag_index = frag._frag_index
        is_first = frag._is_first
        has_more = frag._has_more
        frag_data = frag._frag_data

        logger.debug(f'Fragment: packet_id={packet_id}, index={frag_index}, first={is_first}, more={has_more}')

        # Initialize assembly buffer if needed
        if packet_id not in self._packet_assembly:
            self._packet_assembly[packet_id] = {}
            self._packet_first_seen[packet_id] = False

        # Track first fragment
        if is_first:
            self._packet_first_seen[packet_id] = True

        # Store fragment
        self._packet_assembly[packet_id][frag_index] = frag_data

        # Check if complete (has_more == False means this is last fragment)
        if not has_more:
            logger.debug(f'Last fragment received for packet_id={packet_id}')

            # Verify we have first fragment
            if not self._packet_first_seen[packet_id]:
                logger.error(f'Received last fragment before first for packet_id={packet_id}')
                return

            # Reassemble message (sort by index)
            fragments = self._packet_assembly[packet_id]
            indices = sorted(fragments.keys())

            # Check for missing fragments
            if indices != list(range(len(indices))):
                logger.error(f'Missing fragments for packet_id={packet_id}: {indices}')
                return

            # Concatenate fragments
            message = b''.join(fragments[i] for i in indices)

            logger.debug(f'Reassembled message: {len(message)} bytes')

            # Decrypt and verify integrity
            plaintext = EncryptedFragment.decrypt_message(self._enc_key, self._auth_key, message)

            if plaintext is None:
                logger.error(f'Decryption or integrity check failed for packet_id={packet_id}')
                # Clean up
                del self._packet_assembly[packet_id]
                del self._packet_first_seen[packet_id]
                return

            # Parse key-value
            if len(plaintext) < 1:
                logger.error(f'Plaintext too short: {len(plaintext)} bytes')
                del self._packet_assembly[packet_id]
                del self._packet_first_seen[packet_id]
                return

            key_length = plaintext[0]
            if len(plaintext) < 1 + key_length:
                logger.error(f'Invalid key_length: {key_length}')
                del self._packet_assembly[packet_id]
                del self._packet_first_seen[packet_id]
                return

            key = plaintext[1:1+key_length]
            value = plaintext[1+key_length:]

            logger.info(f'Packet reassembled: key_len={len(key)}, value_len={len(value)}')

            # Put to output queue
            self._packet_outqueue.put({'key': key, 'value': value, 'key_length': key_length})

            # Clean up
            del self._packet_assembly[packet_id]
            del self._packet_first_seen[packet_id]


# ============================================================================
# DNS Query Reader (unchanged)
# ============================================================================

class DnsQueryReader(object):
    """
    Read DNS queries from network interface using tshark.
    """

    def __init__(self, interface='en0', domain='.example.com'):
        self._interface = interface
        self._domain = domain
        self._tshark_cmd = [
            'tshark', '-l', '-i', interface,
            '-T', 'fields', '-e', 'dns.qry.name',
            'udp port 53'
        ]

    def __iter__(self):
        logger.info(f'Starting DNS capture on interface {self._interface}')
        proc = subprocess.Popen(
            self._tshark_cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            bufsize=1
        )

        for line in iter(proc.stdout.readline, b''):
            dns_query = line.decode('utf-8', errors='ignore').strip()
            if dns_query.endswith(self._domain):
                logger.debug(f'DNS query: {dns_query[:50]}...')
                yield dns_query


# ============================================================================
# Key Generation and Encoding
# ============================================================================

def encode_key_hex(key_bytes, key_type='key'):
    """
    Encode key bytes to hex string with prefix.

    Args:
        key_bytes: 32-byte key
        key_type: 'key', 'auth', or 'frag'

    Returns:
        str: mj_<type>_<64_hex_chars>
    """
    if len(key_bytes) != 32:
        raise ValueError(f'Key must be 32 bytes, got {len(key_bytes)}')
    hex_str = key_bytes.hex()
    return f'mj_{key_type}_{hex_str}'


def decode_key_hex(key_str):
    """
    Decode hex key string to bytes.

    Args:
        key_str: mj_<type>_<64_hex_chars>

    Returns:
        bytes: 32-byte key
    """
    # Strip prefix
    if key_str.startswith('mj_'):
        parts = key_str.split('_')
        if len(parts) == 3:
            hex_str = parts[2]
        else:
            hex_str = key_str
    else:
        hex_str = key_str

    try:
        key_bytes = bytes.fromhex(hex_str)
    except ValueError as e:
        raise ValueError(f'Invalid hex string: {e}')

    if len(key_bytes) != 32:
        raise ValueError(f'Key must be 32 bytes, got {len(key_bytes)}')

    return key_bytes


def get_keypair_hex():
    """
    Generate three 32-byte keys for new protocol.

    Returns:
        dict with 'enc_key', 'auth_key', 'frag_key' (hex encoded)
    """
    enc_key = secrets.token_bytes(32)
    auth_key = secrets.token_bytes(32)
    frag_key = secrets.token_bytes(32)

    return {
        'enc_key': encode_key_hex(enc_key, 'key'),
        'auth_key': encode_key_hex(auth_key, 'auth'),
        'frag_key': encode_key_hex(frag_key, 'frag')
    }


def validate_domain(domain):
    """Validate domain format."""
    if not domain.startswith('.'):
        return False, 'Domain must start with dot (.)'
    if len(domain) < 3:
        return False, 'Domain too short'
    if len(domain) > 253:
        return False, 'Domain too long (max 253)'
    return True, 'OK'


# ============================================================================
# Packet Handlers (infrastructure - mostly unchanged)
# ============================================================================

class PacketHandler:
    """Base class for packet handlers."""
    def handle(self, packet):
        raise NotImplementedError()


class StdoutHandler(PacketHandler):
    """Print packets to stdout as JSON."""
    def handle(self, packet):
        key = packet.get('key', b'')
        value = packet.get('value', b'')
        key_length = packet.get('key_length', 0)

        # JSON output
        output = {
            'timestamp': datetime.datetime.utcnow().isoformat() + 'Z',
            'event': 'packet_reassembled',
            'key_length': key_length,
            'value_length': len(value),
            'key_preview': key[:100].decode('utf-8', errors='replace') if key else '',
            'value_preview': value[:100].decode('utf-8', errors='replace')
        }

        print(json.dumps(output), flush=True)
        logger.info(f'Packet: key_len={key_length}, value_len={len(value)}')


class SMTPHandler(PacketHandler):
    """Forward packets via SMTP email."""
    def __init__(self, config):
        self.server = config.get('server')
        self.port = config.getint('port', 587)
        self.use_tls = config.getboolean('start-tls', True)
        self.username = config.get('username')
        self.password = config.get('password')
        self.from_addr = config.get('from')
        self.to_addr = config.get('to')

    def handle(self, packet):
        key = packet.get('key', b'')
        value = packet.get('value', b'')

        # Build email
        subject = f'Mumbojumbo: {key.decode("utf-8", errors="replace")[:50] if key else "Data"}'
        body = f'Key: {key.decode("utf-8", errors="replace")}\n\n'
        body += f'Value ({len(value)} bytes):\n{value.decode("utf-8", errors="replace")[:1000]}'

        msg = MIMEText(body)
        msg['Subject'] = subject
        msg['From'] = self.from_addr
        msg['To'] = self.to_addr

        try:
            with smtplib.SMTP(self.server, self.port, timeout=10) as smtp:
                if self.use_tls:
                    smtp.starttls()
                if self.username and self.password:
                    smtp.login(self.username, self.password)
                smtp.send_message(msg)
            logger.info('Email sent successfully')
        except Exception as e:
            logger.error(f'SMTP error: {type(e).__name__}: {e}')


# ============================================================================
# Configuration and Logging
# ============================================================================

def setup_logging(verbose=False, logfile='mumbojumbo.log'):
    """Configure logging."""
    global logger
    logger = logging.getLogger(__name__)
    logger.setLevel(logging.DEBUG)
    logger.handlers = []

    # File handler (always DEBUG)
    file_handler = logging.handlers.RotatingFileHandler(
        logfile, maxBytes=10*1024*1024, backupCount=5
    )
    file_handler.setLevel(logging.DEBUG)
    file_formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
    file_handler.setFormatter(file_formatter)
    logger.addHandler(file_handler)

    # Stderr handler (only if verbose)
    if verbose:
        stderr_handler = logging.StreamHandler(sys.stderr)
        stderr_handler.setLevel(logging.DEBUG)
        stderr_formatter = logging.Formatter('%(levelname)s: %(message)s')
        stderr_handler.setFormatter(stderr_formatter)
        logger.addHandler(stderr_handler)

    return logger


def check_tshark():
    """Check if tshark is available."""
    try:
        subprocess.run(['tshark', '--version'], capture_output=True, check=True)
        return True
    except (subprocess.CalledProcessError, FileNotFoundError):
        return False


def check_root_permissions():
    """Check if running with root/sudo."""
    return os.geteuid() == 0


# ============================================================================
# Main
# ============================================================================

def option_parser():
    """Parse command-line options."""
    parser = optparse.OptionParser(usage='%prog [options]')

    # Keys
    parser.add_option('--enc-key', dest='enc_key', help='Encryption key (mj_key_...)')
    parser.add_option('--auth-key', dest='auth_key', help='Auth key (mj_auth_...)')
    parser.add_option('--frag-key', dest='frag_key', help='Fragment key (mj_frag_...)')

    # Network
    parser.add_option('-i', '--interface', dest='interface', default='en0',
                      help='Network interface (default: en0)')
    parser.add_option('-d', '--domain', dest='domain', default='.example.com',
                      help='DNS domain suffix (default: .example.com)')

    # Actions
    parser.add_option('--gen-keys', dest='gen_keys', action='store_true',
                      help='Generate keys and print environment variables')

    # Logging
    parser.add_option('-v', '--verbose', dest='verbose', action='store_true',
                      help='Verbose output to stderr')

    return parser


def main():
    """Main entry point."""
    parser = option_parser()
    opts, args = parser.parse_args()

    # Setup logging
    setup_logging(verbose=opts.verbose)

    # Generate keys
    if opts.gen_keys:
        keys = get_keypair_hex()
        domain = opts.domain if opts.domain != '.example.com' else f'.{secrets.token_hex(3)}.{secrets.token_hex(3)}'

        print('# Mumbojumbo v2.0 Configuration')
        print(f'export MUMBOJUMBO_ENC_KEY={keys["enc_key"]}')
        print(f'export MUMBOJUMBO_AUTH_KEY={keys["auth_key"]}')
        print(f'export MUMBOJUMBO_FRAG_KEY={keys["frag_key"]}')
        print(f'export MUMBOJUMBO_DOMAIN={domain}')
        return 0

    # Get keys from opts or environment
    enc_key = opts.enc_key or os.getenv('MUMBOJUMBO_ENC_KEY')
    auth_key = opts.auth_key or os.getenv('MUMBOJUMBO_AUTH_KEY')
    frag_key = opts.frag_key or os.getenv('MUMBOJUMBO_FRAG_KEY')
    domain = opts.domain or os.getenv('MUMBOJUMBO_DOMAIN', '.example.com')

    if not enc_key or not auth_key or not frag_key:
        logger.error('Keys not provided. Use --gen-keys or set environment variables.')
        return 1

    # Decode keys
    try:
        enc_key_bytes = decode_key_hex(enc_key)
        auth_key_bytes = decode_key_hex(auth_key)
        frag_key_bytes = decode_key_hex(frag_key)
    except ValueError as e:
        logger.error(f'Invalid key: {e}')
        return 1

    # Validate domain
    valid, msg = validate_domain(domain)
    if not valid:
        logger.error(f'Invalid domain: {msg}')
        return 1

    # Check requirements
    if not check_tshark():
        logger.error('tshark not found. Install with: brew install wireshark (macOS) or apt-get install tshark (Linux)')
        return 1

    if not check_root_permissions():
        logger.error('Root permissions required for packet capture. Run with sudo.')
        return 1

    logger.info('Mumbojumbo v2.0 starting')
    logger.info(f'Domain: {domain}')
    logger.info(f'Interface: {opts.interface}')

    # Setup fragment class
    frag_cls = DnsFragment.bind(
        domain=domain,
        enc_key=enc_key_bytes,
        auth_key=auth_key_bytes,
        frag_key=frag_key_bytes
    )

    # Setup packet engine
    engine = PacketEngine(
        frag_cls=frag_cls,
        enc_key=enc_key_bytes,
        auth_key=auth_key_bytes,
        frag_key=frag_key_bytes
    )

    # Setup handlers
    handlers = [StdoutHandler()]

    # Start DNS capture and processing
    reader = DnsQueryReader(interface=opts.interface, domain=domain)

    logger.info('Ready to receive packets')

    try:
        for dns_query in reader:
            # Process fragment
            engine.from_wire(dns_query)

            # Handle completed packets
            while not engine.packet_outqueue.empty():
                packet = engine.packet_outqueue.get()
                for handler in handlers:
                    handler.handle(packet)

    except KeyboardInterrupt:
        logger.info('Shutting down')
        return 0
    except Exception as e:
        logger.error(f'Fatal error: {type(e).__name__}: {e}')
        logger.debug(traceback.format_exc())
        return 1


if __name__ == '__main__':
    sys.exit(main())
