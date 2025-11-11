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
# import pdb

import nacl.public
from mumbojumbo import (
    PacketEngine,
    Fragment,
    PublicFragment,
    DnsPublicFragment
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
        self.assertIsInstance(forwarder._port, int)
        self.assertEqual(forwarder._port, 587)

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
