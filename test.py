#!/usr/bin/env python3
# -*- coding: utf-8 -*-
#
# known attacks:
#  replay (no timestamp)
#  hmac shared secret issues
#
#  b32enc(type + id + countOrIdx [ + data]) + domain
#
import hashlib
import logging
import os
import random
import subprocess
import sys
import time
import unittest
import tempfile
import datetime
# import pdb

import nacl.public
from mumbojumbo import (
    PacketEngine,
    Fragment,
    PublicFragment,
    DnsPublicFragment,
    PacketHandler,
    StdoutHandler,
    SMTPHandler,
    FileHandler,
    ExecuteHandler
)


# logging.basicConfig(level=logging.DEBUG)
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


def ping_hosts(hosts):
    logger.debug('ping_hosts()')
    plist = []
    devnull = open(os.devnull, 'w')
    for host in hosts:
        cmd = 'ping -c1 -w1 {0}'.format(host)
        time.sleep(0.03)
        logger.debug('ping_hosts(): ' + cmd)
        p = subprocess.Popen(cmd.split(), stderr=devnull)
        plist.append(p)
    logger.debug('ping_hosts(): plist wait()')
    for p in plist:
        p.wait()
    devnull.close()


class DnsQueryReader(object):

    def __init__(self, iff):
        self._iff = iff

    def __iter__(self):
        cmd = 'tshark -li eth0 -T fields -e dns.qry.name udp port 53'
        self._p = p = subprocess.Popen(cmd.split(), stdout=subprocess.PIPE)
        line = p.stdout.readline().strip()
        if isinstance(line, bytes):
            line = line.decode('utf-8')
        while line:
            logger.debug('parsing ' + line)
            yield line
            logger.debug('reading next query...')
            line = p.stdout.readline().strip()
            if isinstance(line, bytes):
                line = line.decode('utf-8')
        p.wait()

    def __del__(self):
        self._p.terminate()
        self._p.wait()


def test_client(packet_engine, rounds=10):
    name_server = DnsQueryWriter()
    for i in range(rounds):
        logger.info('ROUND({0})'.format(i))
        data = nacl.public.random(random.randint(200, 400))
        logger.info('DATA({0}): {1}'.format(len(data), repr(data)))
        datahash = hashlib.sha256(data).digest()
        logger.info('HASH({0}): {1}'.format(len(datahash), repr(datahash)))
        name_server.query_all(packet_engine.to_wire(data))
        time.sleep(0.1)
        name_server.query_all(packet_engine.to_wire(datahash))
        time.sleep(0.1)
    print('SUCCESS sent {0} packets of random data plus hashes'.format(rounds))


def test_server(packet_engine, rounds=10, **kw):
    query_sniffer = DnsQueryReader(**kw)
    i = 0
    while rounds > 0:
        logger.info('ROUND({0})'.format(i))
        #
        # getting packet with random data
        #
        data = None
        datahash = None
        for dnsname in query_sniffer:
            packet_engine.from_wire(dnsname)
            if not packet_engine.packet_outqueue.empty():
                if not data:
                    data = packet_engine.packet_outqueue.get()
                    logger.info('DATA({0}): {1}'.format(len(data),
                                                        repr(data)))
                else:
                    datahash = packet_engine.packet_outqueue.get()
                    logger.info('HASH({0}): {1}'.format(len(datahash),
                                                        repr(datahash)))
                    assert datahash == hashlib.sha256(data).digest()
                    logger.info('hash OK!')
                    data = None
                    rounds -= 1
            if rounds == 0:
                break
    logger.info('SUCCESS all {0} packets had correct hashes'.format(rounds))


class DnsQueryWriter(object):

    DEFAULT_ADDR = ('127.0.0.1', 53)

    def __init__(self, name_server=DEFAULT_ADDR):
        if type(name_server) is str:
            name_server = (name_server, 53)
        self._name_server = name_server

    def _get_socket(self):
        from socket import (
            socket, AF_INET, SOCK_DGRAM
        )
        s = socket(AF_INET, SOCK_DGRAM)
        s.connect(self._name_server)
        return s

    def _build_query(self, name):
        s = b''
        s += nacl.public.random(2)  # query id
        s += b'\x01\x00'  # standard query
        s += b'\x00\x01'  # queries
        s += b'\x00\x00'  # answer rr:s
        s += b'\x00\x00'  # authority rr:s
        s += b'\x00\x00'  # additional rr:s
        for part in name.split('.'):
            s += bytes([len(part)])
            s += part.encode('ascii')
        s += b'\x00'
        s += b'\x00\x01'  # type: a, host address
        s += b'\x00\x01'  # class: in
        return s

    def query(self, name):
        s = self._get_socket()
        try:
            qry = self._build_query(name)
            s.send(qry)
        finally:
            s.close()

    def query_all(self, names):
        s = self._get_socket()
        try:
            for name in names:
                qry = self._build_query(name)
                s.send(qry)
        finally:
            s.close()


def test_dns_query():
    name_server = DnsQueryWriter()
    names = 'www.dn.se www.kernel.org whatever.asdqwe.com'.split()
    name_server.query_all(names)


def test_performance():
    _key = r'nQV+KhrNM2kbJGCrm+LlfPfiCodLV9A4Ldok4f6gvD4='
    import base64
    private_key = nacl.public.PrivateKey(base64.b64decode(_key))
    # For SealedBox: client uses public_key only, server uses private_key only
    pfcls_encrypt = DnsPublicFragment.bind(public_key=private_key.public_key)
    pfcls_decrypt = DnsPublicFragment.bind(private_key=private_key)
    packet_engine_encrypt = PacketEngine(pfcls_encrypt)
    packet_engine_decrypt = PacketEngine(pfcls_decrypt)
    data = nacl.public.random(1024)

    count = 1024
    lst = []
    t1 = time.time()
    for i in range(count):
        for item in packet_engine_encrypt.to_wire(data):
            lst.append(item)
    t2 = time.time()
    for item in lst:
        packet_engine_decrypt.from_wire(item)
    t3 = time.time()

    while not packet_engine_decrypt.packet_outqueue.empty():
        packet_engine_decrypt.packet_outqueue.get()
        count -= 1
    assert count == 0

    print('Offline processing of 1024 messages, 1024 bytes per message:')
    print('send time: {0:.2f}s'.format(t2 - t1))
    print('recv time: {0:.2f}s'.format(t3 - t2))
    print('message fragment count:', len(lst))


class MyTestMixin(object):

    def serialize_deserialize(self, frag_cls, frag_index, frag_count,
                              frag_data):
        '''
            test deserialize(serialize()) of frag_cls
        '''
        fr1 = frag_cls(frag_index=frag_index, frag_count=frag_count,
                       frag_data=frag_data)
        fr2 = fr1.deserialize(fr1.serialize())
        assert fr1._packet_id == fr2._packet_id
        assert frag_index == fr1._frag_index == fr2._frag_index
        assert frag_count == fr1._frag_count == fr2._frag_count
        assert frag_data == fr1.frag_data == fr2.frag_data

    def multi_serialize_deserialize(self, frag_cls):
        '''
            test deserialize(serialize()) of frag_cls with:
            * zero-length data
            * one byte length data
            * 100 random data lengths between 0 and 1024
        '''
        frag_index = random.randint(0, 100)
        frag_count = random.randint(frag_index + 1, frag_index + 100)
        datalist = [b'']
        datalist += [b'a']
        datalist += [os.urandom(random.randint(0, 4096)) for i in range(100)]
        for data in datalist:
            self.serialize_deserialize(frag_cls, frag_index, frag_count, data)

    def public_serialize_deserialize(self, pfcls1, pfcls2, frag_index,
                                     frag_count, frag_data):
        '''
            test deserialize(serialize()) of frag_cls
        '''
        fr1 = pfcls1(frag_index=frag_index, frag_count=frag_count,
                     frag_data=frag_data)
        fr2 = pfcls2().deserialize(fr1.serialize())
        assert fr1._packet_id == fr2._packet_id
        assert frag_index == fr1._frag_index == fr2._frag_index
        assert frag_count == fr1._frag_count == fr2._frag_count
        assert frag_data == fr1.frag_data == fr2.frag_data

    def multi_public_serialize_deserialize(self, pfcls1, pfcls2):
        '''
            test deserialize(serialize()) of frag_cls with:
            * zero-length data
            * one byte length data
            * 100 random data lengths between 0 and 1024
        '''
        frag_index = random.randint(0, 100)
        frag_count = random.randint(frag_index + 1, frag_index + 100)
        datalist = [b'']
        datalist += [b'a']
        datalist += [nacl.public.random(random.randint(0, 4096))
                     for i in range(100)]
        for data in datalist:
            self.public_serialize_deserialize(pfcls1, pfcls2, frag_index,
                                              frag_count, data)


class Test_Fragment(unittest.TestCase):

    def test1(self):
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


class Test_PublicFragment(unittest.TestCase, MyTestMixin):

    def do_test_cls(self, cls, **kw):
        # For SealedBox: Only need one keypair (server keypair)
        # Client encrypts with public_key, server decrypts with private_key
        server_privkey = nacl.public.PrivateKey.generate()
        pfcls_encrypt = cls.bind(public_key=server_privkey.public_key, **kw)
        pfcls_decrypt = cls.bind(private_key=server_privkey, **kw)
        self.multi_public_serialize_deserialize(pfcls_encrypt, pfcls_decrypt)

    def test_classes(self):
        self.do_test_cls(PublicFragment)
        self.do_test_cls(DnsPublicFragment, domain='.asd.qwe')

    def test2(self):
        self.serialize_deserialize(Fragment, frag_index=3, frag_count=4,
                                   frag_data=b'asdqwe')
        self.multi_serialize_deserialize(Fragment)


class Test_PacketEngine(unittest.TestCase, MyTestMixin):

    def setUp(self):
        packet_data_lst = [b'']
        packet_data_lst += [b'a']
        packet_data_lst += [nacl.public.random(random.randint(1, 2048))
                            for i in range(64)]
        # For SealedBox: Only need one keypair (server keypair)
        server_privkey = nacl.public.PrivateKey.generate()
        pfcls_encrypt = DnsPublicFragment.bind(public_key=server_privkey.public_key)
        pfcls_decrypt = DnsPublicFragment.bind(private_key=server_privkey)
        self.packet_data_lst = packet_data_lst
        self.pfcls_encrypt = pfcls_encrypt
        self.pfcls_decrypt = pfcls_decrypt

    def do_test_cls(self, cls, **kw):
        pe_encrypt = PacketEngine(frag_cls=self.pfcls_encrypt, **kw)
        pe_decrypt = PacketEngine(frag_cls=self.pfcls_decrypt, **kw)
        for packet_data in self.packet_data_lst:
            for wire_data in pe_encrypt.to_wire(packet_data=packet_data):
                pe_decrypt.from_wire(wire_data=wire_data)
            out_data = pe_decrypt.packet_outqueue.get()
            assert packet_data == out_data
            assert pe_decrypt.packet_outqueue.empty()

    def test_classes(self):
        self.do_test_cls(PacketEngine, max_frag_data_len=100)


class Test_SMTPErrorHandling(unittest.TestCase):
    """Test SMTP error handling to ensure robustness."""

    def setUp(self):
        """Set up test fixtures."""
        from unittest.mock import Mock, patch
        from mumbojumbo import SMTPForwarder
        self.Mock = Mock
        self.patch = patch
        self.SMTPForwarder = SMTPForwarder

    def test_port_type_conversion(self):
        """Test that port is converted to int."""
        forwarder = self.SMTPForwarder(
            server='localhost',
            port='587',  # String port
            from_='test@example.com',
            to='dest@example.com'
        )
        # SMTPForwarder now wraps SMTPHandler, check the inner handler
        self.assertIsInstance(forwarder._handler._port, int)
        self.assertEqual(forwarder._handler._port, 587)

    def test_connection_refused(self):
        """Test handling of connection refused errors."""
        import socket
        forwarder = self.SMTPForwarder(
            server='localhost',
            port=9999,  # Non-existent port
            from_='test@example.com',
            to='dest@example.com'
        )

        with self.patch('smtplib.SMTP') as mock_smtp:
            mock_smtp.side_effect = ConnectionRefusedError('Connection refused')
            result = forwarder.sendmail('Test', 'Test body')
            self.assertFalse(result)

    def test_timeout_error(self):
        """Test handling of timeout errors."""
        import socket
        forwarder = self.SMTPForwarder(
            server='localhost',
            port=587,
            from_='test@example.com',
            to='dest@example.com'
        )

        with self.patch('smtplib.SMTP') as mock_smtp:
            mock_smtp.side_effect = socket.timeout('Connection timed out')
            result = forwarder.sendmail('Test', 'Test body')
            self.assertFalse(result)

    def test_auth_error(self):
        """Test handling of authentication errors."""
        import smtplib
        forwarder = self.SMTPForwarder(
            server='localhost',
            port=587,
            from_='test@example.com',
            to='dest@example.com',
            username='baduser',
            password='badpass'
        )

        with self.patch('smtplib.SMTP') as mock_smtp_class:
            mock_smtp = self.Mock()
            mock_smtp_class.return_value = mock_smtp
            mock_smtp.login.side_effect = smtplib.SMTPAuthenticationError(535, 'Authentication failed')
            result = forwarder.sendmail('Test', 'Test body')
            self.assertFalse(result)

    def test_recipient_refused(self):
        """Test handling of recipient refused errors."""
        import smtplib
        forwarder = self.SMTPForwarder(
            server='localhost',
            port=587,
            from_='test@example.com',
            to='bad@example.com'
        )

        with self.patch('smtplib.SMTP') as mock_smtp_class:
            mock_smtp = self.Mock()
            mock_smtp_class.return_value = mock_smtp
            mock_smtp.sendmail.side_effect = smtplib.SMTPRecipientsRefused({'bad@example.com': (550, 'User unknown')})
            result = forwarder.sendmail('Test', 'Test body')
            self.assertFalse(result)

    def test_successful_send(self):
        """Test successful email sending."""
        forwarder = self.SMTPForwarder(
            server='localhost',
            port=587,
            from_='test@example.com',
            to='dest@example.com',
            username='user',
            password='pass'
        )

        with self.patch('smtplib.SMTP') as mock_smtp_class:
            mock_smtp = self.Mock()
            mock_smtp_class.return_value = mock_smtp
            result = forwarder.sendmail('Test Subject', 'Test body')
            self.assertTrue(result)
            mock_smtp.sendmail.assert_called_once()
            mock_smtp.quit.assert_called()

    def test_dns_error(self):
        """Test handling of DNS resolution errors."""
        import socket
        forwarder = self.SMTPForwarder(
            server='nonexistent.invalid.domain.example',
            port=587,
            from_='test@example.com',
            to='dest@example.com'
        )

        with self.patch('smtplib.SMTP') as mock_smtp:
            mock_smtp.side_effect = socket.gaierror('Name or service not known')
            result = forwarder.sendmail('Test', 'Test body')
            self.assertFalse(result)


class Test_KeyEncoding(unittest.TestCase):
    """Test key encoding/decoding with mj_priv_ and mj_pub_ prefixes."""

    def test_encode_public_key(self):
        """Test encoding public key with mj_pub_ prefix."""
        from mumbojumbo import encode_key_hex
        import nacl.public

        private_key = nacl.public.PrivateKey.generate()
        pub_key_bytes = private_key.public_key.encode()

        encoded = encode_key_hex(pub_key_bytes, key_type='pub')

        # Check prefix
        self.assertTrue(encoded.startswith('mj_pub_'))

        # Check length (mj_pub_ = 7 chars + 64 hex chars = 71 total)
        self.assertEqual(len(encoded), 71)

        # Check hex encoding
        hex_part = encoded[7:]
        self.assertEqual(pub_key_bytes.hex(), hex_part)

    def test_encode_private_key(self):
        """Test encoding private key with mj_priv_ prefix."""
        from mumbojumbo import encode_key_hex
        import nacl.public

        private_key = nacl.public.PrivateKey.generate()
        priv_key_bytes = private_key.encode()

        encoded = encode_key_hex(priv_key_bytes, key_type='priv')

        # Check prefix
        self.assertTrue(encoded.startswith('mj_priv_'))

        # Check length (mj_priv_ = 8 chars + 64 hex chars = 72 total)
        self.assertEqual(len(encoded), 72)

        # Check hex encoding
        hex_part = encoded[8:]
        self.assertEqual(priv_key_bytes.hex(), hex_part)

    def test_encode_invalid_key_type(self):
        """Test that invalid key_type raises ValueError."""
        from mumbojumbo import encode_key_hex
        import nacl.public

        private_key = nacl.public.PrivateKey.generate()
        key_bytes = private_key.encode()

        with self.assertRaises(ValueError) as ctx:
            encode_key_hex(key_bytes, key_type='invalid')
        self.assertIn('must be "priv" or "pub"', str(ctx.exception))

    def test_decode_public_key(self):
        """Test decoding public key with mj_pub_ prefix."""
        from mumbojumbo import encode_key_hex, decode_key_hex
        import nacl.public

        private_key = nacl.public.PrivateKey.generate()
        pub_key_bytes = private_key.public_key.encode()

        encoded = encode_key_hex(pub_key_bytes, key_type='pub')
        decoded = decode_key_hex(encoded)

        self.assertEqual(pub_key_bytes, decoded)

    def test_decode_private_key(self):
        """Test decoding private key with mj_priv_ prefix."""
        from mumbojumbo import encode_key_hex, decode_key_hex
        import nacl.public

        private_key = nacl.public.PrivateKey.generate()
        priv_key_bytes = private_key.encode()

        encoded = encode_key_hex(priv_key_bytes, key_type='priv')
        decoded = decode_key_hex(encoded)

        self.assertEqual(priv_key_bytes, decoded)

    def test_decode_invalid_prefix(self):
        """Test that keys without proper prefix raise ValueError."""
        from mumbojumbo import decode_key_hex

        # Test completely invalid prefix
        with self.assertRaises(ValueError) as ctx:
            decode_key_hex('invalid_prefix_1234567890abcdef')
        self.assertIn('must start with "mj_priv_" or "mj_pub_"', str(ctx.exception))

        # Test legacy mj_ prefix (no longer supported)
        with self.assertRaises(ValueError) as ctx:
            decode_key_hex('mj_1234567890abcdef')
        self.assertIn('must start with "mj_priv_" or "mj_pub_"', str(ctx.exception))

    def test_decode_invalid_hex(self):
        """Test that invalid hex raises ValueError."""
        from mumbojumbo import decode_key_hex

        with self.assertRaises(ValueError) as ctx:
            decode_key_hex('mj_pub_GGGGGG')  # G is not valid hex
        self.assertIn('Invalid hex key format', str(ctx.exception))

    def test_get_nacl_keypair_hex(self):
        """Test keypair generation with new prefixes."""
        from mumbojumbo import get_nacl_keypair_hex, decode_key_hex
        import nacl.public

        priv_str, pub_str = get_nacl_keypair_hex()

        # Check prefixes
        self.assertTrue(priv_str.startswith('mj_priv_'))
        self.assertTrue(pub_str.startswith('mj_pub_'))

        # Check lengths
        self.assertEqual(len(priv_str), 72)
        self.assertEqual(len(pub_str), 71)

        # Decode and verify they form a valid keypair
        priv_bytes = decode_key_hex(priv_str)
        pub_bytes = decode_key_hex(pub_str)

        # Reconstruct keypair and verify public key matches
        private_key = nacl.public.PrivateKey(priv_bytes)
        self.assertEqual(private_key.public_key.encode(), pub_bytes)

    def test_round_trip_encoding(self):
        """Test encode->decode round trip for both key types."""
        from mumbojumbo import encode_key_hex, decode_key_hex
        import nacl.public

        private_key = nacl.public.PrivateKey.generate()

        # Test private key round trip
        priv_bytes = private_key.encode()
        priv_encoded = encode_key_hex(priv_bytes, key_type='priv')
        priv_decoded = decode_key_hex(priv_encoded)
        self.assertEqual(priv_bytes, priv_decoded)

        # Test public key round trip
        pub_bytes = private_key.public_key.encode()
        pub_encoded = encode_key_hex(pub_bytes, key_type='pub')
        pub_decoded = decode_key_hex(pub_encoded)
        self.assertEqual(pub_bytes, pub_decoded)


class Test_PacketHandlers(unittest.TestCase):
    """Test handler base class and concrete implementations."""

    def setUp(self):
        """Set up test fixtures."""
        self.test_data = b'Test packet data'
        self.test_query = 'test.example.com'
        self.test_timestamp = datetime.datetime.now(datetime.timezone.utc)

    def test_handler_base_class_not_implemented(self):
        """Test that PacketHandler base class requires handle() implementation."""
        handler = PacketHandler()
        with self.assertRaises(NotImplementedError):
            handler.handle(self.test_data, self.test_query, self.test_timestamp)

    def test_stdout_handler_success(self):
        """Test StdoutHandler outputs JSON successfully."""
        from io import StringIO
        import json
        import sys

        # Capture stdout
        captured_output = StringIO()
        original_stdout = sys.stdout
        sys.stdout = captured_output

        try:
            handler = StdoutHandler()
            result = handler.handle(self.test_data, self.test_query, self.test_timestamp)

            # Check result
            self.assertTrue(result)

            # Parse JSON output
            output = captured_output.getvalue().strip()
            data = json.loads(output)

            # Verify JSON structure
            self.assertEqual(data['event'], 'packet_reassembled')
            self.assertEqual(data['query'], self.test_query)
            self.assertEqual(data['data_length'], len(self.test_data))
            self.assertIn('data_preview', data)
            self.assertIn('timestamp', data)

        finally:
            sys.stdout = original_stdout

    def test_stdout_handler_binary_data(self):
        """Test StdoutHandler handles binary data by converting to hex."""
        from io import StringIO
        import json
        import sys

        binary_data = b'\x00\x01\x02\xff'

        captured_output = StringIO()
        original_stdout = sys.stdout
        sys.stdout = captured_output

        try:
            handler = StdoutHandler()
            result = handler.handle(binary_data, self.test_query, self.test_timestamp)

            self.assertTrue(result)

            output = captured_output.getvalue().strip()
            data = json.loads(output)

            # Binary data should be hex-encoded in preview
            self.assertEqual(data['data_preview'], binary_data.hex())

        finally:
            sys.stdout = original_stdout

    def test_stdout_handler_empty_data(self):
        """Test StdoutHandler handles empty data."""
        from io import StringIO
        import json
        import sys

        captured_output = StringIO()
        original_stdout = sys.stdout
        sys.stdout = captured_output

        try:
            handler = StdoutHandler()
            result = handler.handle(b'', self.test_query, self.test_timestamp)

            self.assertTrue(result)

            output = captured_output.getvalue().strip()
            data = json.loads(output)

            self.assertEqual(data['data_length'], 0)
            self.assertEqual(data['data_preview'], '')

        finally:
            sys.stdout = original_stdout

    def test_stdout_handler_large_data_truncation(self):
        """Test StdoutHandler truncates large data preview."""
        from io import StringIO
        import json
        import sys

        # Create data longer than 100 characters
        large_data = b'A' * 200

        captured_output = StringIO()
        original_stdout = sys.stdout
        sys.stdout = captured_output

        try:
            handler = StdoutHandler()
            result = handler.handle(large_data, self.test_query, self.test_timestamp)

            self.assertTrue(result)

            output = captured_output.getvalue().strip()
            data = json.loads(output)

            # Preview should be truncated to 100 chars + '...'
            self.assertEqual(len(data['data_preview']), 103)
            self.assertTrue(data['data_preview'].endswith('...'))
            self.assertEqual(data['data_length'], 200)

        finally:
            sys.stdout = original_stdout

    def test_file_handler_hex_format(self):
        """Test FileHandler writes data in hex format."""
        with tempfile.NamedTemporaryFile(mode='r', delete=False) as tmp:
            tmp_path = tmp.name

        try:
            handler = FileHandler(path=tmp_path, format='hex')
            result = handler.handle(self.test_data, self.test_query, self.test_timestamp)

            self.assertTrue(result)

            # Read and verify file contents
            with open(tmp_path, 'r') as f:
                content = f.read()

            # Check header is present
            self.assertIn('query: test.example.com', content)
            self.assertIn('length: 16', content)
            self.assertIn('format: hex', content)

            # Check data is hex-encoded
            self.assertIn(self.test_data.hex(), content)

        finally:
            if os.path.exists(tmp_path):
                os.unlink(tmp_path)

    def test_file_handler_base64_format(self):
        """Test FileHandler writes data in base64 format."""
        import base64

        with tempfile.NamedTemporaryFile(mode='r', delete=False) as tmp:
            tmp_path = tmp.name

        try:
            handler = FileHandler(path=tmp_path, format='base64')
            result = handler.handle(self.test_data, self.test_query, self.test_timestamp)

            self.assertTrue(result)

            with open(tmp_path, 'r') as f:
                content = f.read()

            # Check data is base64-encoded
            expected_b64 = base64.b64encode(self.test_data).decode('ascii')
            self.assertIn(expected_b64, content)
            self.assertIn('format: base64', content)

        finally:
            if os.path.exists(tmp_path):
                os.unlink(tmp_path)

    def test_file_handler_raw_format(self):
        """Test FileHandler writes data in raw format."""
        with tempfile.NamedTemporaryFile(mode='rb', delete=False) as tmp:
            tmp_path = tmp.name

        try:
            handler = FileHandler(path=tmp_path, format='raw')
            result = handler.handle(self.test_data, self.test_query, self.test_timestamp)

            self.assertTrue(result)

            with open(tmp_path, 'rb') as f:
                content = f.read()

            # Check raw data is present
            self.assertIn(self.test_data, content)
            # Header should also be present (as UTF-8)
            self.assertIn(b'query: test.example.com', content)

        finally:
            if os.path.exists(tmp_path):
                os.unlink(tmp_path)

    def test_file_handler_invalid_format(self):
        """Test FileHandler rejects invalid format."""
        with self.assertRaises(ValueError) as ctx:
            FileHandler(path='/tmp/test', format='invalid')
        self.assertIn('Must be raw, hex, or base64', str(ctx.exception))

    def test_file_handler_append_mode(self):
        """Test FileHandler appends to existing file."""
        with tempfile.NamedTemporaryFile(mode='r', delete=False) as tmp:
            tmp_path = tmp.name

        try:
            handler = FileHandler(path=tmp_path, format='hex')

            # Write first packet
            handler.handle(b'first', 'query1.com', self.test_timestamp)

            # Write second packet
            handler.handle(b'second', 'query2.com', self.test_timestamp)

            # Verify both packets are in file
            with open(tmp_path, 'r') as f:
                content = f.read()

            self.assertIn('first'.encode().hex(), content)
            self.assertIn('second'.encode().hex(), content)
            self.assertIn('query1.com', content)
            self.assertIn('query2.com', content)

        finally:
            if os.path.exists(tmp_path):
                os.unlink(tmp_path)

    def test_file_handler_empty_data(self):
        """Test FileHandler handles empty data."""
        with tempfile.NamedTemporaryFile(mode='r', delete=False) as tmp:
            tmp_path = tmp.name

        try:
            handler = FileHandler(path=tmp_path, format='hex')
            result = handler.handle(b'', self.test_query, self.test_timestamp)

            self.assertTrue(result)

            with open(tmp_path, 'r') as f:
                content = f.read()

            self.assertIn('length: 0', content)

        finally:
            if os.path.exists(tmp_path):
                os.unlink(tmp_path)

    def test_file_handler_permission_error(self):
        """Test FileHandler handles file permission errors."""
        # Try to write to a read-only directory (that doesn't exist)
        handler = FileHandler(path='/nonexistent/path/file.txt', format='hex')
        result = handler.handle(self.test_data, self.test_query, self.test_timestamp)

        self.assertFalse(result)

    def test_file_handler_large_data(self):
        """Test FileHandler handles large data."""
        with tempfile.NamedTemporaryFile(mode='r', delete=False) as tmp:
            tmp_path = tmp.name

        try:
            # Create 10MB of data
            large_data = b'X' * (10 * 1024 * 1024)

            handler = FileHandler(path=tmp_path, format='hex')
            result = handler.handle(large_data, self.test_query, self.test_timestamp)

            self.assertTrue(result)

            with open(tmp_path, 'r') as f:
                content = f.read()

            self.assertIn('length: 10485760', content)

        finally:
            if os.path.exists(tmp_path):
                os.unlink(tmp_path)

    def test_execute_handler_success(self):
        """Test ExecuteHandler runs command successfully."""
        # Use a simple echo command that should work on Unix/Mac
        handler = ExecuteHandler(command='cat', timeout=5)
        result = handler.handle(self.test_data, self.test_query, self.test_timestamp)

        self.assertTrue(result)

    def test_execute_handler_with_env_vars(self):
        """Test ExecuteHandler passes environment variables."""
        # Create a script that echoes environment variables
        with tempfile.NamedTemporaryFile(mode='w', delete=False, suffix='.sh') as tmp:
            tmp.write('#!/bin/bash\n')
            tmp.write('echo "Query: $MUMBOJUMBO_QUERY"\n')
            tmp.write('echo "Length: $MUMBOJUMBO_LENGTH"\n')
            tmp.write('echo "Timestamp: $MUMBOJUMBO_TIMESTAMP"\n')
            tmp_path = tmp.name

        try:
            os.chmod(tmp_path, 0o755)

            handler = ExecuteHandler(command=tmp_path, timeout=5)
            result = handler.handle(self.test_data, self.test_query, self.test_timestamp)

            self.assertTrue(result)

        finally:
            if os.path.exists(tmp_path):
                os.unlink(tmp_path)

    def test_execute_handler_failure(self):
        """Test ExecuteHandler handles command failure."""
        # Use a command that will fail
        handler = ExecuteHandler(command='false', timeout=5)
        result = handler.handle(self.test_data, self.test_query, self.test_timestamp)

        self.assertFalse(result)

    def test_execute_handler_timeout(self):
        """Test ExecuteHandler handles timeout."""
        # Command that sleeps longer than timeout
        handler = ExecuteHandler(command='sleep 10', timeout=1)
        result = handler.handle(self.test_data, self.test_query, self.test_timestamp)

        self.assertFalse(result)

    def test_execute_handler_stdin(self):
        """Test ExecuteHandler passes data via stdin."""
        # Use a script that reads stdin
        with tempfile.NamedTemporaryFile(mode='w', delete=False, suffix='.sh') as tmp:
            tmp.write('#!/bin/bash\n')
            tmp.write('cat > /dev/null && echo "success"\n')  # Read stdin and succeed
            tmp_path = tmp.name

        try:
            os.chmod(tmp_path, 0o755)

            handler = ExecuteHandler(command=tmp_path, timeout=5)
            result = handler.handle(self.test_data, self.test_query, self.test_timestamp)

            self.assertTrue(result)

        finally:
            if os.path.exists(tmp_path):
                os.unlink(tmp_path)

    def test_execute_handler_empty_data(self):
        """Test ExecuteHandler handles empty data."""
        handler = ExecuteHandler(command='cat', timeout=5)
        result = handler.handle(b'', self.test_query, self.test_timestamp)

        self.assertTrue(result)

    def test_execute_handler_command_not_found(self):
        """Test ExecuteHandler handles command not found."""
        handler = ExecuteHandler(command='nonexistent_command_12345', timeout=5)
        result = handler.handle(self.test_data, self.test_query, self.test_timestamp)

        self.assertFalse(result)

    def test_execute_handler_large_stdin_data(self):
        """Test ExecuteHandler handles large data via stdin."""
        # Create 1MB of data
        large_data = b'Z' * (1024 * 1024)

        handler = ExecuteHandler(command='wc -c', timeout=10)
        result = handler.handle(large_data, self.test_query, self.test_timestamp)

        self.assertTrue(result)

    def test_execute_handler_shell_special_chars(self):
        """Test ExecuteHandler handles shell special characters safely."""
        # Create script that echoes the data length from environment
        with tempfile.NamedTemporaryFile(mode='w', delete=False, suffix='.sh') as tmp:
            tmp.write('#!/bin/bash\n')
            tmp.write('test -n "$MUMBOJUMBO_LENGTH" && exit 0 || exit 1\n')
            tmp_path = tmp.name

        try:
            os.chmod(tmp_path, 0o755)

            # Use data with special characters
            special_data = b'test; echo "injected"; #'

            handler = ExecuteHandler(command=tmp_path, timeout=5)
            result = handler.handle(special_data, self.test_query, self.test_timestamp)

            self.assertTrue(result)

        finally:
            if os.path.exists(tmp_path):
                os.unlink(tmp_path)

    def test_smtp_handler_with_mock(self):
        """Test SMTPHandler with mocked SMTP connection."""
        from unittest.mock import Mock, patch

        handler = SMTPHandler(
            server='localhost',
            port=587,
            from_='test@example.com',
            to='dest@example.com',
            starttls=True,
            username='user',
            password='pass'
        )

        with patch('smtplib.SMTP') as mock_smtp_class:
            mock_smtp = Mock()
            mock_smtp_class.return_value = mock_smtp

            result = handler.handle(self.test_data, self.test_query, self.test_timestamp)

            self.assertTrue(result)
            mock_smtp.sendmail.assert_called_once()
            mock_smtp.quit.assert_called()

    def test_smtp_handler_connection_error(self):
        """Test SMTPHandler handles connection errors gracefully."""
        from unittest.mock import patch
        import socket

        handler = SMTPHandler(
            server='localhost',
            port=9999,
            from_='test@example.com',
            to='dest@example.com'
        )

        with patch('smtplib.SMTP') as mock_smtp:
            mock_smtp.side_effect = ConnectionRefusedError('Connection refused')
            result = handler.handle(self.test_data, self.test_query, self.test_timestamp)

            self.assertFalse(result)

    def test_smtp_handler_sender_refused(self):
        """Test SMTPHandler handles sender refused errors."""
        from unittest.mock import Mock, patch
        import smtplib

        handler = SMTPHandler(
            server='localhost',
            port=587,
            from_='invalid@example.com',
            to='dest@example.com'
        )

        with patch('smtplib.SMTP') as mock_smtp_class:
            mock_smtp = Mock()
            mock_smtp_class.return_value = mock_smtp
            mock_smtp.sendmail.side_effect = smtplib.SMTPSenderRefused(550, 'Sender refused', 'invalid@example.com')
            result = handler.handle(self.test_data, self.test_query, self.test_timestamp)

            self.assertFalse(result)

    def test_smtp_handler_data_error(self):
        """Test SMTPHandler handles data errors."""
        from unittest.mock import Mock, patch
        import smtplib

        handler = SMTPHandler(
            server='localhost',
            port=587,
            from_='test@example.com',
            to='dest@example.com'
        )

        with patch('smtplib.SMTP') as mock_smtp_class:
            mock_smtp = Mock()
            mock_smtp_class.return_value = mock_smtp
            mock_smtp.sendmail.side_effect = smtplib.SMTPDataError(550, 'Message too large')
            result = handler.handle(self.test_data, self.test_query, self.test_timestamp)

            self.assertFalse(result)

    def test_smtp_handler_general_smtp_exception(self):
        """Test SMTPHandler handles general SMTP exceptions."""
        from unittest.mock import Mock, patch
        import smtplib

        handler = SMTPHandler(
            server='localhost',
            port=587,
            from_='test@example.com',
            to='dest@example.com'
        )

        with patch('smtplib.SMTP') as mock_smtp_class:
            mock_smtp = Mock()
            mock_smtp_class.return_value = mock_smtp
            mock_smtp.sendmail.side_effect = smtplib.SMTPException('General SMTP error')
            result = handler.handle(self.test_data, self.test_query, self.test_timestamp)

            self.assertFalse(result)

    def test_smtp_handler_binary_data(self):
        """Test SMTPHandler handles binary data by converting to hex."""
        from unittest.mock import Mock, patch

        binary_data = b'\x00\x01\x02\xff'

        handler = SMTPHandler(
            server='localhost',
            port=587,
            from_='test@example.com',
            to='dest@example.com'
        )

        with patch('smtplib.SMTP') as mock_smtp_class:
            mock_smtp = Mock()
            mock_smtp_class.return_value = mock_smtp
            result = handler.handle(binary_data, self.test_query, self.test_timestamp)

            self.assertTrue(result)
            # Verify sendmail was called with hex-encoded data
            call_args = mock_smtp.sendmail.call_args
            message_body = call_args[0][2]
            self.assertIn(binary_data.hex(), message_body)

    def test_smtp_handler_empty_data(self):
        """Test SMTPHandler handles empty data."""
        from unittest.mock import Mock, patch

        handler = SMTPHandler(
            server='localhost',
            port=587,
            from_='test@example.com',
            to='dest@example.com'
        )

        with patch('smtplib.SMTP') as mock_smtp_class:
            mock_smtp = Mock()
            mock_smtp_class.return_value = mock_smtp
            result = handler.handle(b'', self.test_query, self.test_timestamp)

            self.assertTrue(result)
            mock_smtp.sendmail.assert_called_once()

    def test_smtp_handler_no_starttls(self):
        """Test SMTPHandler works without STARTTLS."""
        from unittest.mock import Mock, patch

        handler = SMTPHandler(
            server='localhost',
            port=25,
            from_='test@example.com',
            to='dest@example.com',
            starttls=False
        )

        with patch('smtplib.SMTP') as mock_smtp_class:
            mock_smtp = Mock()
            mock_smtp_class.return_value = mock_smtp
            result = handler.handle(self.test_data, self.test_query, self.test_timestamp)

            self.assertTrue(result)
            # Verify starttls was not called
            mock_smtp.starttls.assert_not_called()

    def test_smtp_handler_no_auth(self):
        """Test SMTPHandler works without authentication."""
        from unittest.mock import Mock, patch

        handler = SMTPHandler(
            server='localhost',
            port=25,
            from_='test@example.com',
            to='dest@example.com'
        )

        with patch('smtplib.SMTP') as mock_smtp_class:
            mock_smtp = Mock()
            mock_smtp_class.return_value = mock_smtp
            result = handler.handle(self.test_data, self.test_query, self.test_timestamp)

            self.assertTrue(result)
            # Verify login was not called
            mock_smtp.login.assert_not_called()


class Test_HandlerPipeline(unittest.TestCase):
    """Test handler pipeline integration."""

    def test_multiple_handlers_in_sequence(self):
        """Test running multiple handlers in sequence."""
        from io import StringIO
        import sys
        import json

        test_data = b'Pipeline test'
        test_query = 'test.example.com'
        test_timestamp = datetime.datetime.now(datetime.timezone.utc)

        # Create temp file for FileHandler
        with tempfile.NamedTemporaryFile(mode='r', delete=False) as tmp:
            tmp_path = tmp.name

        try:
            # Create handler pipeline
            handlers = [
                StdoutHandler(),
                FileHandler(path=tmp_path, format='hex'),
                ExecuteHandler(command='cat > /dev/null', timeout=5)
            ]

            # Capture stdout for StdoutHandler
            captured_output = StringIO()
            original_stdout = sys.stdout
            sys.stdout = captured_output

            try:
                # Run all handlers
                results = []
                for handler in handlers:
                    result = handler.handle(test_data, test_query, test_timestamp)
                    results.append(result)

                # All should succeed
                self.assertTrue(all(results))

                # Verify stdout handler output
                output = captured_output.getvalue().strip()
                data = json.loads(output)
                self.assertEqual(data['event'], 'packet_reassembled')

                # Verify file handler wrote data
                with open(tmp_path, 'r') as f:
                    file_content = f.read()
                self.assertIn(test_data.hex(), file_content)

            finally:
                sys.stdout = original_stdout

        finally:
            if os.path.exists(tmp_path):
                os.unlink(tmp_path)

    def test_handler_failure_does_not_stop_pipeline(self):
        """Test that one handler failure doesn't stop other handlers."""
        from io import StringIO
        import sys
        import json

        test_data = b'Test data'
        test_query = 'test.example.com'
        test_timestamp = datetime.datetime.now(datetime.timezone.utc)

        # Create handler pipeline with a failing handler in the middle
        handlers = [
            StdoutHandler(),
            ExecuteHandler(command='false', timeout=5),  # This will fail
            ExecuteHandler(command='true', timeout=5)    # This should still run
        ]

        captured_output = StringIO()
        original_stdout = sys.stdout
        sys.stdout = captured_output

        try:
            results = []
            for handler in handlers:
                result = handler.handle(test_data, test_query, test_timestamp)
                results.append(result)

            # First should succeed, second should fail, third should succeed
            self.assertTrue(results[0])
            self.assertFalse(results[1])
            self.assertTrue(results[2])

        finally:
            sys.stdout = original_stdout


def main(*args):
    import base64
    # For SealedBox: Only need one keypair (server keypair)
    _server_privkey = 'nQV+KhrNM2kbJGCrm+LlfPfiCodLV9A4Ldok4f6gvD4='
    server_privkey = nacl.public.PrivateKey(base64.b64decode(_server_privkey))

    # Client only needs server's public key
    pfcls_client = DnsPublicFragment.bind(public_key=server_privkey.public_key)
    packet_engine_client = PacketEngine(pfcls_client)

    # Server uses private key to decrypt
    pfcls_server = DnsPublicFragment.bind(private_key=server_privkey)
    packet_engine_server = PacketEngine(pfcls_server)

    if len(args):
        if args[0] == '--test-server':
            logger.info('Now run ./mumbojumbo.py --test-client in other term')
            test_server(packet_engine_server, rounds=100, iff='eth0')
            sys.exit()

        elif args[0] == '--test-client':
            test_client(packet_engine_client, rounds=100)
            sys.exit()

        elif args[0] == '--test-dns':
            test_dns_query()
            sys.exit()

        elif args[0] == '--test-performance':
            test_performance()
            sys.exit()


if __name__ == '__main__':
    import unittest
    main(*sys.argv[1:])
    unittest.main()
