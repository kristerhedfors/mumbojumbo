#!/usr/bin/env python3
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

import nacl.public
import nacl.secret


# Global logger - initialize with basic config, will be reconfigured in main()
logging.basicConfig(level=logging.DEBUG)
global logger
logger = logging.getLogger(__name__)


def b32enc(s):
    return base64.b32encode(s).replace(b'=', b'')


def b32dec(s):
    r = len(s) % 8
    if r:
        s += b'=' * (8 - r)
    return base64.b32decode(s)


class MJException(Exception):
    pass


class Bindable(object):

    @classmethod
    def bind(cls, *args, **kw):
        return functools.partial(cls, *args, **kw)


class BaseFragment(Bindable):

    def __init__(self, frag_data=''):
        self._frag_data = frag_data

    @property
    def frag_data(self):
        return self._frag_data

    def serialize(self):
        return self._frag_data

    def deserialize(self, raw):
        self.__class__(frag_data=raw)


class Fragment(BaseFragment):
    '''
        Packet format:
            u64 packet_id
            u32 frag_index
            u32 frag_count
            u16 len(frag_data)
            bytes frag_data
    '''
    def __init__(self, packet_id=None, frag_index=0, frag_count=1, **kw):
        self._packet_id = packet_id or PacketEngine.gen_packet_id()
        self._frag_index = frag_index
        self._frag_count = frag_count
        super(Fragment, self).__init__(**kw)

    def _htonl_pack(self, val):
        nval = socket.htonl(val)
        return struct.pack('I', nval)

    def _htons_pack(self, val):
        nval = socket.htons(val)
        return struct.pack('H', nval)

    def _htonll_pack(self, val):
        # Pack u64 in big-endian (network byte order)
        return struct.pack('!Q', val)

    def _unpack_ntohl(self, s):
        assert len(s) == 4
        nval = struct.unpack('I', s)[0]
        return socket.ntohl(nval)

    def _unpack_ntohs(self, s):
        assert len(s) == 2
        nval = struct.unpack('H', s)[0]
        return socket.ntohs(nval)

    def _unpack_ntohll(self, s):
        # Unpack u64 from big-endian (network byte order)
        assert len(s) == 8
        return struct.unpack('!Q', s)[0]

    def serialize(self):
        ser = b''
        ser += self._htonll_pack(self._packet_id)  # u64 (8 bytes)
        ser += self._htonl_pack(self._frag_index)  # u32 (4 bytes)
        ser += self._htonl_pack(self._frag_count)  # u32 (4 bytes)
        ser += self._htons_pack(len(self._frag_data))  # u16 (2 bytes)
        ser += self._frag_data
        return ser

    def deserialize(self, raw):
        packet_id = self._unpack_ntohll(raw[:8])  # u64, bytes 0-8
        frag_index = self._unpack_ntohl(raw[8:12])  # u32, bytes 8-12
        frag_count = self._unpack_ntohl(raw[12:16])  # u32, bytes 12-16
        frag_data_len = self._unpack_ntohs(raw[16:18])  # u16, bytes 16-18
        frag_data = raw[18:]  # bytes 18+
        try:
            assert frag_data_len == len(frag_data)
        except:
            logger.debug('bad frag_data_len: %d' % frag_data_len)
            raise
        assert 1 <= frag_count
        try:
            assert frag_index < frag_count
        except:
            logger.debug('bad frag_count: %d' % frag_count)
            raise
        # Pass keys if they exist (for PublicFragment subclasses)
        kw = {'packet_id': packet_id, 'frag_index': frag_index,
              'frag_count': frag_count, 'frag_data': frag_data}
        if hasattr(self, '_server_key'):
            kw['server_key'] = self._server_key
        if hasattr(self, '_client_key'):
            kw['client_key'] = self._client_key
        if hasattr(self, '_domain'):
            kw['domain'] = self._domain
        return self.__class__(**kw)


class PublicFragment(Fragment):
    '''
        Packet fragment encrypted/decrypted using nacl.public.SealedBox().
        One-way anonymous encryption using only the server's public key.
    '''
    def __init__(self, server_key=None, client_key=None, **kw):
        # Auto-parse hex keys if strings are provided
        if isinstance(server_key, str):
            server_key_bytes = decode_key_hex(server_key)
            server_key = nacl.public.PrivateKey(server_key_bytes)
        if isinstance(client_key, str):
            client_key_bytes = decode_key_hex(client_key)
            client_key = nacl.public.PublicKey(client_key_bytes)

        self._server_key = server_key
        self._client_key = client_key
        # For encryption (client side): only needs client_key
        # For decryption (server side): only needs server_key
        if client_key is not None:
            self._sealedbox_encrypt = nacl.public.SealedBox(client_key)
        else:
            self._sealedbox_encrypt = None
        if server_key is not None:
            self._sealedbox_decrypt = nacl.public.SealedBox(server_key)
        else:
            self._sealedbox_decrypt = None
        super(PublicFragment, self).__init__(**kw)

    def serialize(self):
        plaintext = super(PublicFragment, self).serialize()
        # SealedBox handles nonce internally - no need for manual nonce management
        ciphertext = self._sealedbox_encrypt.encrypt(plaintext)
        return ciphertext

    def deserialize(self, ciphertext):
        plaintext = b''
        try:
            plaintext = self._sealedbox_decrypt.decrypt(ciphertext)
        except:
            logger.debug('decrypt exception:' + traceback.format_exc())
            raise
        logger.debug('decrypted {0} bytes of data'.format(len(plaintext)))
        logger.debug('{0}'.format(repr(plaintext)))
        return super(PublicFragment, self).deserialize(plaintext)


def _split2len(s, n):
    assert n > 0
    if s == b'':
        return [b'']

    def _f(s, n):
        while s:
            yield s[:n]
            s = s[n:]
    return list(_f(s, n))


class DnsPublicFragment(PublicFragment):
    '''
        DNS-tunnel-style Packet fragment encrypted/decrypted using
        nacl.public.Box().

        Has the shape of:
            '{Base32Encoded_PublicFragment}{tld}'
    '''
    DEFAULT_TLD = '.asd.qwe'

    def __init__(self, domain=DEFAULT_TLD, **kw):
        self._domain = domain
        super(DnsPublicFragment, self).__init__(**kw)

    def serialize(self):
        ser = super(DnsPublicFragment, self).serialize()
        serb32 = self._b32enc(ser)
        parts = _split2len(serb32, 63)
        dnsname = '.'.join(parts) + self._domain
        return dnsname

    def deserialize(self, dnsname):
        logger.debug('DnsPublicFragment: deserialize() enter')
        if dnsname.endswith(self._domain):
            serb32 = dnsname[:-len(self._domain)].replace('.', '')
            ser = self._b32dec(serb32)
            val = super(DnsPublicFragment, self).deserialize(ser)
            if val is None:
                logger.debug('DnsPublicFragment: deserialize() error')
            else:
                logger.debug('DnsPublicFragment: deserialize() success')
            return val
        else:
            msg = 'DnsPublicFragment: deserialize() invalid domain: '
            msg += dnsname[:10]
            logger.debug(msg)

    def _b32enc(self, s):
        return base64.b32encode(s).replace(b'=', b'').lower().decode('ascii')

    def _b32dec(self, s):
        s = s.upper().encode('ascii')
        r = len(s) % 8
        if r:
            s += b'=' * (8 - r)
        return base64.b32decode(s)


def calculate_safe_max_fragment_data_len(domain):
    '''
        Calculate safe maximum fragment data size using simplified formula.
        Formula: 83 - len(domain) // 3

        This simplified formula is:
        - Within 0-2 bytes of optimal for typical domains (3-12 chars)
        - Within 5-7 bytes for longer domains (22-33 chars)
        - Always safe (slightly conservative, never exceeds DNS limits)
        - Requires only one arithmetic operation

        Args:
            domain: DNS domain string (e.g., '.example.com')

        Returns:
            Maximum safe fragment data length in bytes

        Raises:
            ValueError: If domain is too long (>143 chars)
    '''
    if len(domain) > 143:
        raise ValueError(f'Domain too long: {len(domain)} chars (max 143)')
    return 83 - len(domain) // 3


class PacketEngine(object):

    #
    # make dynamic or long domain names will fail when
    # fragmenting data!
    #
    MAX_FRAG_DATA_LEN = 80


    @classmethod
    def gen_packet_id(cls):
        # Sequential packet IDs are now managed per-instance
        # This method kept for compatibility but should use instance counter
        return 0

    def __init__(self, frag_cls=None, max_frag_data_len=None):
        self._frag_cls = frag_cls

        # Auto-calculate max_frag_data_len from domain if not provided
        if max_frag_data_len is None:
            # Extract domain from bound fragment class
            if frag_cls is not None and hasattr(frag_cls, 'keywords') and 'domain' in frag_cls.keywords:
                domain = frag_cls.keywords['domain']
                self._max_frag_data_len = calculate_safe_max_fragment_data_len(domain)
                logger.debug(f'Auto-calculated max_frag_data_len={self._max_frag_data_len} for domain={domain}')
            else:
                # Fallback to default if domain not available
                self._max_frag_data_len = self.MAX_FRAG_DATA_LEN
                logger.warning('Could not extract domain from frag_cls, using default MAX_FRAG_DATA_LEN')
        else:
            self._max_frag_data_len = max_frag_data_len

        self._packet_assembly = {}
        self._packet_assembly_counter = {}
        self._packet_outqueue = queue.Queue()
        # Packet ID counter (u64: 0 to 2^64-1, wraps around)
        # Initialize with cryptographically secure random value
        self._next_packet_id = secrets.randbits(64)
        # Track completed packet IDs for replay detection
        self._completed_packet_ids = set()

    @property
    def packet_outqueue(self):
        return self._packet_outqueue

    def to_wire(self, packet_data):
        '''
            Generator yielding zero or more fragments from data.
        '''
        logger.debug('to_wire() len(packet_data)==' + str(len(packet_data)))
        # Use packet ID and increment counter
        packet_id = self._next_packet_id
        self._next_packet_id = (self._next_packet_id + 1) & 0xFFFFFFFFFFFFFFFF  # Wrap at 2^64-1 (u64)
        frag_data_lst = _split2len(packet_data, self._max_frag_data_len)
        frag_count = len(frag_data_lst)
        frag_index = 0
        for frag_data in frag_data_lst:
            frag = self._frag_cls(packet_id=packet_id, frag_index=frag_index,
                                  frag_count=frag_count, frag_data=frag_data)
            wire_data = frag.serialize()
            yield wire_data
            frag_index += 1

    def from_wire(self, wire_data):
        '''
            if wire_data constitutes final missing fragment of a packet:
              put assembled packet to packet_outqueue
        '''
        logger.debug('from_wire() len(wire_data)==' + str(len(wire_data)))
        frag = self._frag_cls().deserialize(wire_data)
        if frag is not None:
            packet_assembly = self._packet_assembly
            packet_id = frag._packet_id
            #
            # get frag_data_lst for packet
            #
            frag_data_lst = None
            if packet_id not in packet_assembly:
                frag_data_lst = [None] * frag._frag_count
                packet_assembly[packet_id] = frag_data_lst
            elif len(packet_assembly[packet_id]) != frag._frag_count:
                logger.error('from_wire(): _frag_count mismatch')
                return
            else:  # packet is known
                frag_data_lst = packet_assembly[packet_id]
            #
            # insert fragment if new
            #
            if frag_data_lst[frag._frag_index] is None:
                counter = self._packet_assembly_counter
                frag_data_lst[frag._frag_index] = frag._frag_data
                if packet_id not in counter:
                    counter[packet_id] = frag._frag_count
                counter[packet_id] -= 1
                if counter[packet_id] < 0:
                    msg = 'from_wire(): counter[packet_id] < 0'
                    logger.error(msg)
                    raise MJException(msg)
                if counter[packet_id] == 0:
                    #
                    # final fragment obtained, return packet
                    #
                    self._finalize_packet(packet_id)

    def _finalize_packet(self, packet_id):
        # Check for replay attack (duplicate packet ID)
        if packet_id in self._completed_packet_ids:
            logger.warning(f'Replay attack detected: packet_id {packet_id} has been completed before')
        else:
            # Add to completed set
            self._completed_packet_ids.add(packet_id)

        frag_data_lst = self._packet_assembly[packet_id]
        packet_data = b''.join(frag_data_lst)
        self.packet_outqueue.put(packet_data)


class DnsQueryReader(object):
    '''
        Use tshark to generate DNS queries.
    '''
    TSHARK = '/usr/bin/tshark'

    def __init__(self, iff='', domain=''):
        self._iff = iff
        self._domain = domain
        self._p = None

    def __iter__(self):
        # Try to find tshark in common locations
        import shutil
        tshark = shutil.which('tshark') or self.TSHARK

        # Use the interface from config, or try to auto-detect
        interface = self._iff
        if not interface:
            # Use cloud-aware auto-detection
            interface = detect_cloud_network_interface()
            if not interface:
                # Final fallback
                interface = 'eth0'
                logger.warning(f'Could not detect interface, using fallback: {interface}')
            else:
                logger.info(f'Auto-detected interface: {interface}')
        else:
            logger.info(f'Using configured interface: {interface}')

        cmd = f'{tshark} -li {interface} -T fields -e dns.qry.name -- udp port 53'
        # Redirect stderr to /dev/null to prevent tshark banner from polluting JSON output
        self._p = p = subprocess.Popen(cmd.split(), stdout=subprocess.PIPE, stderr=subprocess.DEVNULL)
        name = p.stdout.readline().strip()
        if isinstance(name, bytes):
            name = name.decode('utf-8')
        while name:
            logger.debug('parsing ' + name)
            if not self._domain or name.lower().endswith(self._domain):
                yield name
            logger.debug('reading next query...')
            name = p.stdout.readline().strip()
            if isinstance(name, bytes):
                name = name.decode('utf-8')
        p.wait()

    def __del__(self):
        if self._p is not None:
            self._p.terminate()
            self._p.wait()


__usage__ = '''
Usage: python mumbojumbo.py [options]

Quick Start:
  1. Generate keys and domain:
     $ ./mumbojumbo.py --gen-keys > ~/.mumbojumbo_env
     $ source ~/.mumbojumbo_env

  2. Run server (uses env vars automatically):
     $ sudo ./mumbojumbo.py

  3. Send data from client:
     $ echo "data" | ./clients/python/mumbojumbo-client.py -k $MUMBOJUMBO_CLIENT_KEY -d $MUMBOJUMBO_DOMAIN

Environment Variables:
  MUMBOJUMBO_SERVER_KEY  Server private key (overrides config file)
  MUMBOJUMBO_CLIENT_KEY  Server public key (for client use with -k)
  MUMBOJUMBO_DOMAIN      Domain suffix (overrides config file)

Precedence: CLI args > Environment variables > Config file
'''


__config_skel__ = '''\
#
# !! remember to `chmod 0600` this file !!
#
# for use on client-side:
#   domain = .asd.qwe
#   mumbojumbo_client_key = {mumbojumbo_client_key}
#
# Keys are in hex format with mj_srv_ or mj_cli_ prefix for easy identification.
# Format: mj_srv_<64_hex_chars> for server keys
#         mj_cli_<64_hex_chars> for client keys
#

[main]
# Domain including leading dot
domain = .asd.qwe
# Network interface - macOS: en0, en1; Linux: eth0, wlan0
network-interface = en0
# Handler pipeline: comma-separated list of handlers (REQUIRED)
# Available handlers: stdout, smtp, file, execute
handlers = stdout
mumbojumbo-server-key = {mumbojumbo_server_key}
mumbojumbo-client-key = {mumbojumbo_client_key}

[smtp]
server = 127.0.0.1
port = 587
start-tls
username = someuser
password = yourpasswordhere
from = someuser@somehost.xy
to = otheruser@otherhost.xy

[file]
path = /var/log/mumbojumbo-packets.log
# Format: raw, hex (default), or base64
format = hex

[execute]
command = /usr/local/bin/process-packet.sh
# Timeout in seconds
timeout = 5
'''


def option_parser():
    p = optparse.OptionParser(usage=__usage__)
    p.add_option('-c', '--config', metavar='path',
                 help='use this config file')
    p.add_option('-k', '--key', metavar='server_key',
                 help='override mumbojumbo-server-key from config (format: mj_srv_<64_hex_chars>)')
    p.add_option('-d', '--domain', metavar='domain',
                 help='override domain from config (e.g., .example.com)')
    p.add_option('', '--gen-keys', action='store_true',
                 help='generate keys and domain as env var declarations (output can be sourced)')
    p.add_option('', '--gen-conf', action='store_true',
                 help='generate config skeleton file (mumbojumbo.conf)')
    p.add_option('', '--test-handlers', action='store_true',
                 help='test all configured handlers in the pipeline')
    p.add_option('', '--health-check', action='store_true',
                 help='perform health check and exit (for K8s liveness probes)')
    p.add_option('', '--daemon', action='store_true',
                 help='run in daemon mode with signal handling (SIGTERM, SIGINT)')
    p.add_option('-v', '--verbose', action='store_true',
                 help='also print debug logs to stderr (default: logs only to mumbojumbo.log)')
    return p


def encode_key_hex(key_bytes, key_type='cli'):
    '''
        Encode NaCL key bytes to hex format with mj_srv_ or mj_cli_ prefix.
        Format: mj_srv_<hex_encoded_key> or mj_cli_<hex_encoded_key>

        Args:
            key_bytes: Raw key bytes to encode
            key_type: Either 'srv' for server keys or 'cli' for client keys

        Returns:
            Hex-encoded key with appropriate prefix
    '''
    if key_type not in ('srv', 'cli'):
        raise ValueError('key_type must be "srv" or "cli"')
    hex_key = key_bytes.hex()
    return f'mj_{key_type}_{hex_key}'


def decode_key_hex(key_str):
    '''
        Decode hex-formatted key with mj_srv_ or mj_cli_ prefix to bytes.
        Accepts: mj_srv_<hex_encoded_key> or mj_cli_<hex_encoded_key>
        Returns: raw key bytes
    '''
    if key_str.startswith('mj_srv_'):
        hex_key = key_str[7:]  # Remove 'mj_srv_' prefix
    elif key_str.startswith('mj_cli_'):
        hex_key = key_str[7:]  # Remove 'mj_cli_' prefix
    else:
        raise ValueError('Key must start with "mj_srv_" or "mj_cli_" prefix')

    try:
        return bytes.fromhex(hex_key)
    except ValueError as e:
        raise ValueError(f'Invalid hex key format: {e}')


def validate_domain(domain):
    '''
        Validate domain format for DNS-based communication.
        Domain should typically start with a dot (e.g., .example.com).
        Raises ValueError if domain format is invalid.
    '''
    if not domain:
        raise ValueError('Domain cannot be empty')
    if not domain.startswith('.'):
        logger.warning(f'Domain "{domain}" does not start with a dot - this may cause issues with DNS matching')
    # Basic DNS label validation
    if '..' in domain:
        raise ValueError('Domain cannot contain consecutive dots')
    return True


def get_nacl_keypair_hex():
    '''
        Generate NaCL keypair and return as hex strings with mj_srv_ and mj_cli_ prefixes.
        Returns: (server_key_string, client_key_string)
    '''
    private_key = nacl.public.PrivateKey.generate()
    srv = encode_key_hex(private_key.encode(), key_type='srv')
    cli = encode_key_hex(private_key.public_key.encode(), key_type='cli')
    return (srv, cli)


def get_nacl_keypair_base64():
    '''
        DEPRECATED: Use get_nacl_keypair_hex() instead.
        Generate NaCL keypair and return as base64 strings.
    '''
    private_key = nacl.public.PrivateKey.generate()
    priv = base64.b64encode(private_key.encode()).decode('ascii').strip()
    pub = base64.b64encode(private_key.public_key.encode()).decode('ascii').strip()
    return (priv, pub)


class PacketHandler:
    '''
        Base class for packet handlers. All handlers must implement handle() method.
        Handlers process reassembled packets and should never crash the main loop.
    '''
    def handle(self, data: bytes, query: str, timestamp: datetime.datetime) -> bool:
        '''
            Process a reassembled packet.

            Args:
                data: The reassembled packet data (bytes)
                query: The DNS query name that completed the packet
                timestamp: UTC timestamp when packet was reassembled

            Returns:
                True on success, False on failure
        '''
        raise NotImplementedError('Subclasses must implement handle()')


class StdoutHandler(PacketHandler):
    '''
        Output packet metadata as JSON to stdout.
    '''
    def handle(self, data: bytes, query: str, timestamp: datetime.datetime) -> bool:
        try:
            # Convert data to string for preview
            try:
                data_str = data.decode('utf-8')
            except UnicodeDecodeError:
                data_str = data.hex()
                logger.debug('Data is binary, showing as hex in preview')

            # Prepare data preview
            data_preview = data_str[:100] + '...' if len(data_str) > 100 else data_str

            # Output JSON
            output = {
                'timestamp': timestamp.isoformat(),
                'event': 'packet_reassembled',
                'query': query,
                'data_length': len(data),
                'data_preview': data_preview
            }
            print(json.dumps(output), flush=True)
            logger.info(f'Stdout handler: JSON output written')
            return True
        except Exception as e:
            logger.error(f'Stdout handler error: {type(e).__name__}: {e}')
            return False


class SMTPHandler(PacketHandler):
    '''
        Forward packet via email using SMTP.
    '''
    def __init__(self, server='', port=587, from_='', to='', starttls=True,
                 username=None, password=None):
        self._server = server
        self._port = int(port) if port else 587
        self._from = from_
        self._to = to
        self._starttls = starttls
        self._username = username
        self._password = password

    def handle(self, data: bytes, query: str, timestamp: datetime.datetime) -> bool:
        '''Send packet data via email.'''
        # Convert data to string for email
        try:
            data_str = data.decode('utf-8')
        except UnicodeDecodeError:
            data_str = data.hex()
            logger.debug('Binary data, sending as hex in email')

        smtp = None
        try:
            msg = MIMEText(data_str)
            msg.set_charset('utf-8')
            msg['Subject'] = f'Mumbojumbo Packet from {query}'
            msg['From'] = self._from
            msg['To'] = self._to

            logger.debug(f'SMTP handler: connecting to {self._server}:{self._port}')
            smtp = smtplib.SMTP(self._server, port=self._port, timeout=30)
            smtp.ehlo_or_helo_if_needed()

            if self._starttls:
                logger.debug('SMTP handler: starting TLS')
                smtp.starttls()
                smtp.ehlo()

            if self._username or self._password:
                logger.debug(f'SMTP handler: logging in as {self._username}')
                smtp.login(self._username, self._password)

            logger.debug(f'SMTP handler: sending email to {self._to}')
            smtp.sendmail(self._from, [self._to], msg.as_string())
            smtp.quit()
            logger.info(f'SMTP handler: email sent successfully to {self._to}')
            return True

        except (socket.gaierror, socket.herror) as e:
            logger.error(f'SMTP handler DNS/network error: {self._server}:{self._port}: {e}')
            return False
        except socket.timeout as e:
            logger.error(f'SMTP handler timeout: {self._server}:{self._port}: {e}')
            return False
        except ConnectionRefusedError as e:
            logger.error(f'SMTP handler connection refused: {self._server}:{self._port}: {e}')
            return False
        except smtplib.SMTPAuthenticationError as e:
            logger.error(f'SMTP handler authentication failed: {self._username}: {e}')
            return False
        except smtplib.SMTPRecipientsRefused as e:
            logger.error(f'SMTP handler recipient rejected: {self._to}: {e}')
            return False
        except smtplib.SMTPSenderRefused as e:
            logger.error(f'SMTP handler sender rejected: {self._from}: {e}')
            return False
        except smtplib.SMTPDataError as e:
            logger.error(f'SMTP handler data error: {e}')
            return False
        except smtplib.SMTPException as e:
            logger.error(f'SMTP handler error: {e}')
            return False
        except Exception as e:
            logger.error(f'SMTP handler unexpected error: {type(e).__name__}: {e}')
            logger.debug(traceback.format_exc())
            return False
        finally:
            if smtp:
                try:
                    smtp.quit()
                except:
                    pass


class FileHandler(PacketHandler):
    '''
        Write packet data to a file. Supports raw, hex, and base64 formats.
    '''
    def __init__(self, path: str, format: str = 'hex'):
        self._path = path
        if format not in ('raw', 'hex', 'base64'):
            raise ValueError(f'Invalid format: {format}. Must be raw, hex, or base64')
        self._format = format

    def handle(self, data: bytes, query: str, timestamp: datetime.datetime) -> bool:
        try:
            # Format data according to config
            if self._format == 'hex':
                output_data = data.hex()
            elif self._format == 'base64':
                output_data = base64.b64encode(data).decode('ascii')
            else:  # raw
                output_data = data

            # Write to file with metadata header
            with open(self._path, 'ab') as f:
                header = f'# {timestamp.isoformat()} - query: {query} - length: {len(data)} - format: {self._format}\n'
                f.write(header.encode('utf-8'))

                if isinstance(output_data, str):
                    f.write(output_data.encode('utf-8'))
                else:
                    f.write(output_data)

                f.write(b'\n')

            logger.info(f'File handler: wrote {len(data)} bytes to {self._path} (format: {self._format})')
            return True

        except IOError as e:
            logger.error(f'File handler I/O error: {self._path}: {e}')
            return False
        except Exception as e:
            logger.error(f'File handler unexpected error: {type(e).__name__}: {e}')
            logger.debug(traceback.format_exc())
            return False


class ExecuteHandler(PacketHandler):
    '''
        Execute a command with packet data as stdin. Passes metadata as environment variables.
    '''
    def __init__(self, command: str, timeout: int = 30):
        self._command = command
        self._timeout = timeout

    def handle(self, data: bytes, query: str, timestamp: datetime.datetime) -> bool:
        try:
            # Prepare environment variables with metadata
            env = os.environ.copy()
            env['MUMBOJUMBO_QUERY'] = query
            env['MUMBOJUMBO_TIMESTAMP'] = timestamp.isoformat()
            env['MUMBOJUMBO_LENGTH'] = str(len(data))

            logger.debug(f'Execute handler: running command: {self._command}')

            # Execute command with data as stdin
            result = subprocess.run(
                self._command,
                input=data,
                shell=True,
                capture_output=True,
                timeout=self._timeout,
                env=env
            )

            if result.returncode == 0:
                logger.info(f'Execute handler: command succeeded (exit code 0)')
                if result.stdout:
                    logger.debug(f'Execute handler stdout: {result.stdout.decode("utf-8", errors="replace")}')
                return True
            else:
                logger.error(f'Execute handler: command failed (exit code {result.returncode})')
                if result.stderr:
                    logger.error(f'Execute handler stderr: {result.stderr.decode("utf-8", errors="replace")}')
                return False

        except subprocess.TimeoutExpired:
            logger.error(f'Execute handler: command timed out after {self._timeout}s')
            return False
        except FileNotFoundError as e:
            logger.error(f'Execute handler: command not found: {e}')
            return False
        except Exception as e:
            logger.error(f'Execute handler unexpected error: {type(e).__name__}: {e}')
            logger.debug(traceback.format_exc())
            return False


class SMTPForwarder(object):
    '''
        DEPRECATED: Legacy SMTP forwarder. Use SMTPHandler instead.
        Kept for backward compatibility with --test-smtp flag.
    '''
    def __init__(self, server='', port=587, from_='', to='', starttls=True,
                 username=None, password=None):
        self._handler = SMTPHandler(server, port, from_, to, starttls, username, password)

    def sendmail(self, subject='', text='', charset='utf-8'):
        '''Send email via SMTP (legacy interface).'''
        # Convert to handler format - use dummy query and timestamp
        data = text.encode('utf-8') if isinstance(text, str) else text
        return self._handler.handle(data, 'test', datetime.datetime.now(datetime.timezone.utc))


class SecretBox(nacl.secret.SecretBox):
    '''
        Added key expansion to allow arbitrary key lengths.
    '''
    def __init__(self, key, *args, **kw):
        if isinstance(key, str):
            key = key.encode('utf-8')
        key = self.expand(key, 1984)
        super(SecretBox, self).__init__(key, *args, **kw)

    def _expand(self, origkey, key):
        h = hmac.HMAC(key=key, msg=origkey, digestmod=hashlib.sha256)
        return h.digest()

    def expand(self, key, count):
        origkey = key
        for _ in range(count):
            key = self._expand(origkey, key)
        return key


def getpass2(msg):
    '''
        Read secret twice from terminal, repeat until both values match,
        then return secret.
    '''
    sec = None
    while True:
        sec = getpass.getpass(msg + ':')
        sec2 = getpass.getpass(msg + ' again:')
        if sec == sec2:
            break
        print('The values do not match, try again')
    return sec


def setup_logging(verbose=False, logfile='mumbojumbo.log'):
    '''
        Configure logging based on verbose flag:
        - Always log DEBUG+ to rotating file (mumbojumbo.log)
        - If verbose: also log DEBUG+ to console stderr
        - If not verbose: only JSON output to stdout
    '''
    # Get the global logger
    logger = logging.getLogger(__name__)
    logger.setLevel(logging.DEBUG)
    logger.propagate = False  # Don't propagate to root logger

    # Remove any existing handlers (including basicConfig handlers)
    logger.handlers.clear()

    # Also clear root logger handlers to prevent duplicate output
    logging.getLogger().handlers.clear()

    # File handler: always log DEBUG and above to file with rotation
    file_handler = logging.handlers.RotatingFileHandler(
        logfile, maxBytes=10*1024*1024, backupCount=5, encoding='utf-8')
    file_handler.setLevel(logging.DEBUG)
    file_formatter = logging.Formatter(
        '%(asctime)s - %(name)s - %(levelname)s - %(message)s')
    file_handler.setFormatter(file_formatter)
    logger.addHandler(file_handler)

    # Console handler: only if verbose flag is set
    if verbose:
        console_handler = logging.StreamHandler(sys.stderr)
        console_handler.setLevel(logging.DEBUG)
        console_formatter = logging.Formatter(
            '%(asctime)s - %(levelname)s - %(message)s')
        console_handler.setFormatter(console_formatter)
        logger.addHandler(console_handler)


def json_output(event_type, **kwargs):
    '''
        Output parseable JSON to stdout for DNS events.
        Always includes timestamp and event type.
    '''
    output = {
        'timestamp': datetime.datetime.now(datetime.timezone.utc).isoformat(),
        'event': event_type
    }
    output.update(kwargs)
    print(json.dumps(output), flush=True)


# Global flag for graceful shutdown
_shutdown_requested = False


def signal_handler(signum, frame):
    '''Handle SIGTERM and SIGINT for graceful shutdown.'''
    global _shutdown_requested
    signame = signal.Signals(signum).name
    logger.info(f'Received {signame}, initiating graceful shutdown...')
    _shutdown_requested = True


def detect_cloud_network_interface():
    '''
    Detect network interface for cloud environments.
    Returns best guess interface name or None.

    Cloud VMs typically use: ens4 (GCP), eth0 (AWS/Azure), ens5 (AWS Nitro)
    '''
    import platform

    # Try to use 'ip' command on Linux to find active interface
    if platform.system() == 'Linux':
        try:
            result = subprocess.run(['ip', 'route', 'show', 'default'],
                                    capture_output=True, text=True, timeout=2)
            if result.returncode == 0:
                # Parse: "default via X.X.X.X dev INTERFACE ..."
                for line in result.stdout.split('\n'):
                    if 'default' in line and 'dev' in line:
                        parts = line.split()
                        if 'dev' in parts:
                            idx = parts.index('dev')
                            if idx + 1 < len(parts):
                                interface = parts[idx + 1]
                                logger.info(f'Auto-detected network interface: {interface}')
                                return interface
        except (subprocess.TimeoutExpired, FileNotFoundError):
            pass

    # Fallback: try common cloud interface names
    common_interfaces = ['ens4', 'ens5', 'eth0', 'en0', 'wlan0']
    for iface in common_interfaces:
        try:
            # Check if interface exists using ifconfig or ip
            if platform.system() == 'Linux':
                result = subprocess.run(['ip', 'link', 'show', iface],
                                        capture_output=True, timeout=1)
            else:  # macOS
                result = subprocess.run(['ifconfig', iface],
                                        capture_output=True, timeout=1)

            if result.returncode == 0:
                logger.info(f'Found network interface: {iface}')
                return iface
        except (subprocess.TimeoutExpired, FileNotFoundError):
            continue

    logger.warning('Could not auto-detect network interface')
    return None


def check_tshark():
    '''
    Verify tshark is available and accessible.
    Returns (success: bool, tshark_path: str, error_msg: str)
    '''
    import shutil

    tshark = shutil.which('tshark')
    if not tshark:
        return (False, None, 'tshark not found. Install wireshark/tshark package.')

    # Check if we can execute it
    try:
        result = subprocess.run([tshark, '--version'],
                                capture_output=True, timeout=2)
        if result.returncode == 0:
            version_info = result.stdout.decode('utf-8', errors='replace').split('\n')[0]
            return (True, tshark, version_info)
        else:
            return (False, tshark, 'tshark execution failed')
    except subprocess.TimeoutExpired:
        return (False, tshark, 'tshark execution timed out')
    except Exception as e:
        return (False, tshark, f'tshark check failed: {e}')


def check_root_permissions():
    '''
    Check if running with sufficient permissions for packet capture.
    Returns (success: bool, error_msg: str)
    '''
    if os.geteuid() != 0:
        return (False, 'Not running as root. Packet capture requires root privileges (use sudo).')
    return (True, 'Running with root privileges')


def health_check():
    '''
    Perform health check and output status.
    Used for container/K8s liveness probes.
    Returns exit code (0 = healthy, 1 = unhealthy)
    '''
    checks = []

    # Check 1: tshark availability
    tshark_ok, tshark_path, tshark_msg = check_tshark()
    checks.append(('tshark', tshark_ok, tshark_msg))

    # Check 2: root permissions
    root_ok, root_msg = check_root_permissions()
    checks.append(('permissions', root_ok, root_msg))

    # Check 3: log file writable
    try:
        test_log = 'mumbojumbo.log'
        with open(test_log, 'a') as f:
            f.write('')
        checks.append(('log_file', True, f'{test_log} is writable'))
    except IOError as e:
        checks.append(('log_file', False, f'Cannot write to log file: {e}'))

    # Output results
    all_ok = all(ok for _, ok, _ in checks)

    print(json.dumps({
        'status': 'healthy' if all_ok else 'unhealthy',
        'timestamp': datetime.datetime.now(datetime.timezone.utc).isoformat(),
        'checks': [{'name': name, 'status': 'pass' if ok else 'fail', 'message': msg}
                   for name, ok, msg in checks]
    }, indent=2))

    return 0 if all_ok else 1


def startup_validation(network_interface=None, domain=None):
    '''
    Validate environment before starting server.
    Logs warnings and errors but doesn't exit.
    '''
    logger.info('=== Startup Validation ===')

    # Check tshark
    tshark_ok, tshark_path, tshark_msg = check_tshark()
    if tshark_ok:
        logger.info(f'✓ tshark: {tshark_msg}')
    else:
        logger.error(f'✗ tshark: {tshark_msg}')
        logger.error('Server will likely fail to capture packets')

    # Check permissions
    root_ok, root_msg = check_root_permissions()
    if root_ok:
        logger.info(f'✓ Permissions: {root_msg}')
    else:
        logger.warning(f'✗ Permissions: {root_msg}')
        logger.warning('Packet capture may fail without root')

    # Validate network interface
    if network_interface:
        logger.info(f'✓ Network interface configured: {network_interface}')
    else:
        auto_iface = detect_cloud_network_interface()
        if auto_iface:
            logger.info(f'✓ Auto-detected network interface: {auto_iface}')
        else:
            logger.warning('✗ Could not detect network interface, will use default')

    # Validate domain
    if domain:
        logger.info(f'✓ Domain configured: {domain}')
        if not domain.startswith('.'):
            logger.warning(f'  WARNING: Domain should typically start with "." (got: {domain})')

    logger.info('=== Startup Validation Complete ===')


def main():
    (opt, args) = option_parser().parse_args()

    # Setup logging: file always, console only if --verbose
    setup_logging(verbose=opt.verbose)

    # Health check mode - no logging needed
    if opt.health_check:
        sys.exit(health_check())

    if opt.gen_conf:
        (mumbojumbo_server_key, mumbojumbo_client_key) = get_nacl_keypair_hex()

        # Find available filename: mumbojumbo.conf, mumbojumbo.conf.1, etc.
        filename = 'mumbojumbo.conf'
        counter = 0
        while os.path.exists(filename):
            counter += 1
            filename = f'mumbojumbo.conf.{counter}'

        # Write config to file
        config_content = __config_skel__.format(
            mumbojumbo_server_key=mumbojumbo_server_key,
            mumbojumbo_client_key=mumbojumbo_client_key
        )
        with open(filename, 'w') as f:
            f.write(config_content)

        print(f'Created {filename}')
        sys.exit()

    if opt.gen_keys:
        (srv, cli) = get_nacl_keypair_hex()

        # Generate random domain suffix
        import secrets
        random_suffix = ''.join(secrets.choice('abcdefghijklmnopqrstuvwxyz0123456789') for _ in range(8))
        domain = f'.{random_suffix[:4]}.{random_suffix[4:]}'

        # Output as environment variable declarations for easy sourcing
        print(f'export MUMBOJUMBO_SERVER_KEY={srv}')
        print(f'export MUMBOJUMBO_CLIENT_KEY={cli}')
        print(f'export MUMBOJUMBO_DOMAIN={domain}')
        sys.exit()

    # Check if we have minimum required values from env vars or CLI
    has_server_key = opt.key or os.environ.get('MUMBOJUMBO_SERVER_KEY')
    has_domain = opt.domain or os.environ.get('MUMBOJUMBO_DOMAIN')

    # Determine if we need a config file
    config_file = opt.config or 'mumbojumbo.conf'
    use_config_file = os.path.exists(config_file)

    # If no config file and insufficient env vars, error
    if not use_config_file and not (has_server_key and has_domain):
        print('Error: Config file not found and required environment variables not set.')
        print('Either create a config file (--gen-conf) or set environment variables:')
        print('  export MUMBOJUMBO_SERVER_KEY=mj_srv_...')
        print('  export MUMBOJUMBO_DOMAIN=.example.com')
        sys.exit(1)

    # Parse config file if it exists
    config = configparser.ConfigParser(allow_no_value=True)
    if use_config_file:
        config.read(config_file)
        logger.info(f'Loaded config file: {config_file}')

    #
    # Parse handler pipeline
    #
    # Default to stdout if no config file
    if use_config_file and config.has_option('main', 'handlers'):
        handler_names = config.get('main', 'handlers')
        handler_names = [h.strip() for h in handler_names.split(',')]
    elif use_config_file:
        # Config file exists but no handlers specified - error
        logger.error('Missing required "handlers" option in [main] section')
        print('ERROR: Config file must specify "handlers" in [main] section.')
        print('Example: handlers = stdout,smtp,file,execute')
        sys.exit(1)
    else:
        # No config file, use default stdout handler
        handler_names = ['stdout']
        logger.info('No config file - using default stdout handler')

    if not handler_names:
        logger.error('Handler pipeline is empty')
        print('ERROR: At least one handler must be specified.')
        sys.exit(1)

    # Build handler pipeline
    handlers = []
    for handler_name in handler_names:
        try:
            if handler_name == 'stdout':
                handlers.append(StdoutHandler())
                logger.info('Added stdout handler to pipeline')

            elif handler_name == 'smtp':
                if not config.has_section('smtp'):
                    logger.error('smtp handler specified but [smtp] section missing')
                    print('ERROR: smtp handler requires [smtp] config section.')
                    sys.exit(1)

                smtp_items = dict(config.items('smtp'))
                smtp_port = int(smtp_items.get('port', 587))

                smtp_handler = SMTPHandler(
                    server=smtp_items['server'],
                    port=smtp_port,
                    starttls=config.has_option('smtp', 'start-tls'),
                    from_=smtp_items['from'],
                    to=smtp_items['to'],
                    username=smtp_items.get('username', ''),
                    password=smtp_items.get('password', ''))
                handlers.append(smtp_handler)
                logger.info('Added smtp handler to pipeline')

            elif handler_name == 'file':
                if not config.has_section('file'):
                    logger.error('file handler specified but [file] section missing')
                    print('ERROR: file handler requires [file] config section.')
                    sys.exit(1)

                file_items = dict(config.items('file'))
                file_path = file_items['path']
                file_format = file_items.get('format', 'hex')

                file_handler = FileHandler(path=file_path, format=file_format)
                handlers.append(file_handler)
                logger.info(f'Added file handler to pipeline (path={file_path}, format={file_format})')

            elif handler_name == 'execute':
                if not config.has_section('execute'):
                    logger.error('execute handler specified but [execute] section missing')
                    print('ERROR: execute handler requires [execute] config section.')
                    sys.exit(1)

                execute_items = dict(config.items('execute'))
                command = execute_items['command']
                timeout = int(execute_items.get('timeout', 30))

                execute_handler = ExecuteHandler(command=command, timeout=timeout)
                handlers.append(execute_handler)
                logger.info(f'Added execute handler to pipeline (command={command})')

            else:
                logger.error(f'Unknown handler type: {handler_name}')
                print(f'ERROR: Unknown handler type "{handler_name}".')
                print('Valid handlers: stdout, smtp, file, execute')
                sys.exit(1)

        except KeyError as e:
            logger.error(f'Missing required config option for {handler_name} handler: {e}')
            print(f'ERROR: Missing required config option for {handler_name} handler: {e}')
            sys.exit(1)
        except ValueError as e:
            logger.error(f'Invalid config value for {handler_name} handler: {e}')
            print(f'ERROR: Invalid config value for {handler_name} handler: {e}')
            sys.exit(1)

    logger.info(f'Handler pipeline configured: {", ".join(handler_names)}')

    # Test handlers if requested
    if opt.test_handlers:
        logger.info('Testing handler pipeline...')
        print(f'Testing {len(handlers)} handler(s): {", ".join(handler_names)}')

        test_data = b'This is a test packet from --test-handlers'
        test_query = 'test.example.com'
        test_timestamp = datetime.datetime.now(datetime.timezone.utc)

        all_success = True
        for i, (handler, name) in enumerate(zip(handlers, handler_names)):
            print(f'\n[{i+1}/{len(handlers)}] Testing {name} handler...')
            result = handler.handle(test_data, test_query, test_timestamp)
            if result:
                print(f'✓ {name} handler: SUCCESS')
            else:
                print(f'✗ {name} handler: FAILED (check mumbojumbo.log for details)')
                all_success = False

        print('\n' + '='*50)
        if all_success:
            print('SUCCESS: All handlers passed')
            logger.info('Handler pipeline test successful')
            sys.exit(0)
        else:
            print('FAILED: One or more handlers failed')
            logger.error('Handler pipeline test failed')
            sys.exit(1)

    #
    # parse NaCL keys (hex format with mj_srv_ or mj_cli_ prefix)
    # Precedence: CLI args > Environment variables > Config file
    #

    # Get server key with precedence chain
    server_key_str = None
    if opt.key:
        server_key_str = opt.key
        logger.warning('Server key provided via CLI argument - this is visible in process list. Consider using MUMBOJUMBO_SERVER_KEY environment variable instead.')
    elif os.environ.get('MUMBOJUMBO_SERVER_KEY'):
        server_key_str = os.environ.get('MUMBOJUMBO_SERVER_KEY')
        logger.info('Using server key from MUMBOJUMBO_SERVER_KEY environment variable')
    elif use_config_file and config.has_option('main', 'mumbojumbo-server-key'):
        server_key_str = config.get('main', 'mumbojumbo-server-key')
    else:
        logger.error('Missing mumbojumbo-server-key: must be provided via --key, MUMBOJUMBO_SERVER_KEY, or config file')
        print('ERROR: Server key required (use --key, MUMBOJUMBO_SERVER_KEY env var, or config file)')
        sys.exit(1)

    # Get domain with precedence chain
    domain = None
    if opt.domain:
        domain = opt.domain
        logger.info(f'Using domain from CLI argument: {domain}')
    elif os.environ.get('MUMBOJUMBO_DOMAIN'):
        domain = os.environ.get('MUMBOJUMBO_DOMAIN')
        logger.info(f'Using domain from MUMBOJUMBO_DOMAIN environment variable: {domain}')
    elif use_config_file and config.has_option('main', 'domain'):
        domain = config.get('main', 'domain')
    else:
        logger.error('Missing domain: must be provided via --domain, MUMBOJUMBO_DOMAIN, or config file')
        print('ERROR: Domain required (use --domain, MUMBOJUMBO_DOMAIN env var, or config file)')
        sys.exit(1)

    # Validate domain format
    try:
        validate_domain(domain)
    except ValueError as e:
        logger.error(f'Invalid domain format: {e}')
        print(f'ERROR: Invalid domain format: {e}')
        sys.exit(1)

    # Client key from env or config (optional - only used for validation)
    client_key_str = None
    if os.environ.get('MUMBOJUMBO_CLIENT_KEY'):
        client_key_str = os.environ.get('MUMBOJUMBO_CLIENT_KEY')
        logger.info('Using client key from MUMBOJUMBO_CLIENT_KEY environment variable')
    elif use_config_file and config.has_option('main', 'mumbojumbo-client-key'):
        client_key_str = config.get('main', 'mumbojumbo-client-key')

    # Validate key format before passing to bind()
    # bind() will parse them transparently
    try:
        # Just validate they're valid hex keys, don't parse yet
        decode_key_hex(server_key_str)
        if client_key_str:
            decode_key_hex(client_key_str)
    except ValueError as e:
        logger.error(f'Invalid key format: {e}')
        print(f'ERROR: Invalid key format: {e}')
        sys.exit(1)

    # Network interface from config or default to empty (auto-detect)
    network_interface = ''
    if use_config_file and config.has_option('main', 'network-interface'):
        network_interface = config.get('main', 'network-interface')

    logger.info('domain={0}, network_interface={1}'.format(
        domain, network_interface))

    # Daemon mode: setup signal handlers
    if opt.daemon:
        signal.signal(signal.SIGTERM, signal_handler)
        signal.signal(signal.SIGINT, signal_handler)
        logger.info('Daemon mode enabled: registered SIGTERM and SIGINT handlers')

    # Perform startup validation
    startup_validation(network_interface=network_interface, domain=domain)

    #
    # prepare packet fragment class - server uses server_key for decryption
    # Keys are passed as strings and parsed transparently inside PublicFragment
    #
    pf_cls = DnsPublicFragment.bind(domain=domain,
                                    server_key=server_key_str,
                                    client_key=client_key_str)
    #
    # build packet engine based on fragment class
    #
    packet_engine = PacketEngine(pf_cls)

    #
    # initiate DNS query reader for queries under domain
    #
    dns_query_reader = DnsQueryReader(iff=network_interface, domain=domain)

    logger.info(f'Starting DNS query capture on interface={network_interface or "auto"}, domain={domain}')
    logger.info('Server ready - waiting for DNS queries...')

    #
    # iterate sniffed DNS queries do domain;
    # start to decrypt, parse and reassemble fragments
    # into complete packets
    #
    for name in dns_query_reader:
        # Check for shutdown signal in daemon mode
        if opt.daemon and _shutdown_requested:
            logger.info('Graceful shutdown initiated - stopping DNS capture')
            break

        logger.debug('read DNS query for: ' + name)
        #
        # try-catch to prevent deserialization exceptions from causing
        # a DOS attack.
        #
        try:
            packet_engine.from_wire(name)
        except:
            msg = 'exception in from_wire(): '
            msg += traceback.format_exc()
            logger.info(msg)
            continue
        #
        # did a packet complete after reading the last fragment?
        #
        if not packet_engine.packet_outqueue.empty():
            data = packet_engine.packet_outqueue.get()

            # Ensure data is bytes for handlers
            if not isinstance(data, bytes):
                if isinstance(data, str):
                    data = data.encode('utf-8')
                else:
                    data = str(data).encode('utf-8')

            # Get timestamp for this packet
            timestamp = datetime.datetime.now(datetime.timezone.utc)

            logger.info(f'Packet reassembled from query: {name}, length: {len(data)} bytes')
            logger.debug(f'Running handler pipeline with {len(handlers)} handler(s)')

            # Run handler pipeline
            for handler, handler_name in zip(handlers, handler_names):
                try:
                    success = handler.handle(data, name, timestamp)
                    if success:
                        logger.debug(f'{handler_name} handler completed successfully')
                    else:
                        logger.warning(f'{handler_name} handler reported failure')
                except Exception as e:
                    logger.error(f'{handler_name} handler crashed: {type(e).__name__}: {e}')
                    logger.debug(traceback.format_exc())

        sys.stdout.flush()

    # Clean shutdown
    logger.info('DNS query capture stopped')
    if opt.daemon:
        logger.info('Daemon shutdown complete')


if __name__ == '__main__':
    sys.exit(main())
