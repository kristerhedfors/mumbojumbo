#!/usr/bin/env python
# -*- coding: utf-8 -*-
#
# known attacks:
#  replay (no timestamp)
#  hmac shared secret issues
#
#  b32enc(type + id + countOrIdx [ + data]) + tld
import base64
import functools
import hashlib
import logging
import os
import Queue
import random
import re
import struct
import subprocess
import sys
import time
import unittest

import nacl.public


# logging.basicConfig(level=logging.DEBUG)
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


def b32enc(s):
    return base64.b32encode(s).replace('=', '')


def b32dec(s):
    r = len(s) % 8
    if r:
        s += '=' * (8 - r)
    return base64.b32decode(s)


def split2len(s, n):
    def _f(s, n):
        while s:
            yield s[:n]
            s = s[n:]
    return list(_f(s, n))


class Mumbojumbo(object):

    tld = '.mumbojumbo.sometld.xy'
    _hmac_key = 'frutticola94239482349582984010293090943048274389273'
    _max_count = 1024  # max hostname chunks allowed; prevent memory DoS
    _outkey = nacl.public.PrivateKey.generate()
    _inkey = nacl.public.PrivateKey.generate()
    _outbox = nacl.public.Box(_outkey, _inkey.public_key)
    _inbox = nacl.public.Box(_inkey, _outkey.public_key)

    sexpr = r'(?P<b32nonce>[A-Za-z0-9.]+)' +\
            r'\.s(?P<count>[0-9]+)' +\
            tld.replace('.', '\\.')

    dexpr = r'(?P<b32chunkparts>[A-Za-z0-9.]+)' +\
            r'\.d(?P<idx>[0-9]+)' +\
            tld.replace('.', '\\.')

    def __init__(self):
        self._packets = {}
        self._missing_count = {}
        self._history = {}
        self.outq = Queue.Queue()
        self._sexpr = re.compile(self.sexpr)
        self._dexpr = re.compile(self.dexpr)

    def _gen_chunks(self, data):
        encoded = b32enc(data)
        chunks = split2len(encoded, 32)
        return chunks

    def _encrypt(self, plaintext):
        nonce = nacl.public.random(16)
        ciphertext = self._outbox(plaintext, nonce)
        return ciphertext

    def _decrypt(self, ciphertext):
        plaintext = self._inbox(ciphertext)
        return plaintext

    def split(self, plaintext, tld=tld):
        '''
            split data into a start-dnsname and a number of data-dnsnames
        '''
        lst = []
        nonce = nacl.public.random(16)
        ciphertext = self._encrypt(plaintext)
        chunks = self._gen_chunks(ciphertext)
        for (i, chunk) in enumerate(chunks):
            h = self._build_data_packet(nonce, i, chunk, tld)
            lst.append(h)
        h = self._build_start_packet(nonce, len(chunks), tld)
        lst.insert(0, h)
        return lst

    def _build_data_packet(self, nonce, i, chunk, tld):
        h = '.'.join(split2len(b32enc(chunk), 63))
        h += '.d{0}'.format(i)
        h += tld
        return h

    def _build_start_packet(self, nonce, count, tld):
        h = ''
        h += b32enc(nonce)
        h += '.s{0}'.format(count)
        h += tld
        return h

    def _handle_spacket(self, nonce, count):
        if nonce in self._history or nonce in self._packets:
            return
        count = int(count)
        logger.debug('asserting')
        assert count <= self._max_count
        self._packets[nonce] = [None] * count
        self._missing_count[nonce] = count
        logger.debug('S packet done')

    def _handle_dpacket(self, nonce, idx, b32chunkparts):
        if nonce in self._packets:
            if self._packets[nonce][idx] is None:
                chunk = b32dec(b32chunkparts.replace('.', ''))
                self._packets[nonce][idx] = chunk
                self._missing_count[nonce] -= 1
            if self._missing_count[nonce] == 0:
                self._finalize(nonce)

    def parse_dnsname(self, h, tld=tld):
        '''
            Parse some dnsname. Once the start-dnsname
            and all data chunks are obtained, the entire packet
            is reassembled and added to Queue self.outq
        '''
        m = self._sexpr.match(h)
        if m:
            self._handle_spacket(m.group('nonce'),
                                 int(m.group('count')))
            return
        m = self._dexpr.match(h)
        if m:
            self._handle_dpacket(m.group('nonce'),
                                 int(m.group('idx')),
                                 m.group('b32chunkparts'))

    def _finalize(self, nonce):
        b32buf = ''.join(self._packets[nonce])
        buf = b32dec(b32buf)
        self.outq.put(buf)
        del self._packets[nonce]
        del self._missing_count[nonce]
        self._history[nonce] = True


def ping_hosts(hosts):
    plist = []
    devnull = open(os.devnull, 'w')
    for host in hosts:
        cmd = 'ping -c1 -w1 {0}'.format(host)
        time.sleep(0.03)
        p = subprocess.Popen(cmd.split(), stderr=devnull)
    for p in plist:
        p.wait()
    devnull.close()


def read_dns_queries(iff):
    '''
        TODO: add -R dns.qry.name matches '.*tld'
    '''
    cmd = 'tshark -li eth0 -T fields -e dns.qry.name udp port 53'
    p = subprocess.Popen(cmd.split(), stdout=subprocess.PIPE)
    line = p.stdout.readline().strip()
    while line:
        logger.debug('parsing ' + line)
        yield line
        logger.debug('reading next query...')
        line = p.stdout.readline().strip()
    p.wait()


def test_client(rounds=10):
    mj = Mumbojumbo()
    for i in xrange(rounds):
        data = nacl.public.random(random.randint(0, 1024))
        logger.info('DATA({0}): {1}'.format(len(data), repr(data)))
        datahash = hashlib.sha256(data).digest()
        logger.info('HASH({0}): {1}'.format(len(datahash), repr(datahash)))
        ping_hosts(mj.split(data))
        ping_hosts(mj.split(datahash))
    print 'SUCCESS sent {0} packets of random data plus hashes'.format(rounds)


def test_server(rounds=10):
    mj = Mumbojumbo()
    while rounds > 0:
        #
        # getting packet with random data
        #
        data = None
        datahash = None
        for dnsname in read_dns_queries('eth0'):
            mj.parse_dnsname(dnsname)
            if not mj.outq.empty():
                if not data:
                    data = mj.outq.get()
                    logger.info('DATA({0}): {1}'.format(len(data), repr(data)))
                else:
                    datahash = mj.outq.get()
                    logger.info('HASH({0}): {1}'.format(len(datahash),
                                                        repr(datahash)))
                    assert datahash == hashlib.sha256(data).digest()
                    data = datahash = None
                    rounds -= 1
                sys.stdout.flush()
            if rounds == 0:
                break
        sys.stdout.flush()
    print 'SUCCESS all {0} packets had correct hashes'.format(rounds)


class PacketException(Exception):
    pass


class Packet(object):

    def __init__(self, data=''):
        self._data = data

    @property
    def data(self):
        return self._data

    def serialize(self):
        return self._data

    def deserialize(self, raw):
        self.__class__(data=raw)


class Fragment(Packet):
    '''
        Packet format:
            u32 packet_id
            u16 frag_index
            u16 frag_count
            u16 len(data)
            bytes data
    '''

    @classmethod
    def gen_packet_id(cls):
        return struct.unpack('I', nacl.public.random(4))[0]

    def deserialize(self, raw):
        packet_id = struct.unpack('I', raw[:4])[0]
        frag_index = struct.unpack('H', raw[4:6])[0]
        frag_count = struct.unpack('H', raw[6:8])[0]
        datalen = struct.unpack('H', raw[8:10])[0]
        data = raw[10:]
        assert datalen == len(data)
        assert frag_index < frag_count
        return self.__class__(packet_id=packet_id, frag_index=frag_index,
                              frag_count=frag_count, data=data)

    #
    # __init__
    #
    def __init__(self, packet_id=None, frag_index=0, frag_count=1, **kw):
        self._packet_id = packet_id or self.__class__.gen_packet_id()
        self._frag_index = frag_index
        self._frag_count = frag_count
        super(Fragment, self).__init__(**kw)

    def serialize(self):
        ser = ''
        ser += struct.pack('I', self._packet_id)
        ser += struct.pack('H', self._frag_index)
        ser += struct.pack('H', self._frag_count)
        ser += struct.pack('H', len(self._data))
        ser += self._data
        return ser


class PublicFragment(Fragment):
    '''
        Packet fragment encrypted/decrypted using nacl.public.Box().
    '''
    def __init__(self, private_key=None, public_key=None, **kw):
        self._box = nacl.public.Box(private_key, public_key)
        super(PublicFragment, self).__init__(**kw)

    def serialize(self):
        plaintext = super(PublicFragment, self).serialize()
        nonce = nacl.public.random(24)
        ciphertext = self._box.encrypt(plaintext=plaintext, nonce=nonce)
        return ciphertext

    def deserialize(self, ciphertext):
        plaintext = self._box.decrypt(ciphertext=ciphertext)
        return super(PublicFragment, self).deserialize(plaintext)


def _split2len(s, n):
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
    def __init__(self, tld='', **kw):
        self._tld = tld
        super(DnsPublicFragment, self).__init__(**kw)

    def serialize(self):
        ser = super(DnsPublicFragment, self).serialize()
        serb32 = self._b32enc(ser)
        parts = _split2len(serb32, 63)
        dnsname = '.'.join(parts) + self._tld
        # print '>', dnsname
        return dnsname

    def deserialize(self, dnsname):
        # print '<', dnsname
        if dnsname.endswith(self._tld):
            serb32 = dnsname[:-len(self._tld)].replace('.', '')
            ser = self._b32dec(serb32)
            return super(DnsPublicFragment, self).deserialize(ser)

    def _b32enc(self, s):
        return base64.b32encode(s).replace('=', '').lower()

    def _b32dec(self, s):
        s = s.upper()
        r = len(s) % 8
        if r:
            s += '=' * (8 - r)
        return base64.b32decode(s)


class PacketEngine(object):

    def __init__(self, frag_cls=None, max_frag_datalen=None):
        self._frag_cls = frag_cls
        self._max_fragment_datalen = max_frag_datalen
        self._deserialize_queue = Queue.Queue()

    def to_wire(self, packet_data):
        '''
            Generator yielding zero or more fragments from data.
        '''
        for frag_data in _split2len(packet_data, self._max_fragment_datalen):
            frag = self._frag_cls(data=frag_data)
            wire_data = frag.serialize()
            yield wire_data

    def from_wire(self, wire_data):
        frag = self._frag_cls().deserialize(wire_data)


def main(*args):

    if args[0] == '--test-server':
        test_server(rounds=100)
        sys.exit()

    elif args[0] == '--test-client':
        test_client(rounds=100)
        sys.exit()


class MyTestMixin(object):

    def serialize_deserialize(self, frag_cls, frag_index, frag_count, data):
        '''
            test deserialize(serialize()) of frag_cls
        '''
        fr1 = frag_cls(frag_index=frag_index, frag_count=frag_count, data=data)
        fr2 = fr1.deserialize(fr1.serialize())
        assert fr1._packet_id == fr2._packet_id
        assert frag_index == fr1._frag_index == fr2._frag_index
        assert frag_count == fr1._frag_count == fr2._frag_count
        assert data == fr1.data == fr2.data

    def multi_serialize_deserialize(self, frag_cls):
        '''
            test deserialize(serialize()) of frag_cls with:
            * zero-length data
            * one byte length data
            * 100 random data lengths between 0 and 1024
        '''
        frag_index = random.randint(0, 100)
        frag_count = random.randint(frag_index + 1, frag_index + 100)
        datalist = ['']
        datalist += ['a']
        datalist += [os.urandom(random.randint(0, 4096)) for i in xrange(100)]
        for data in datalist:
            self.serialize_deserialize(frag_cls, frag_index, frag_count, data)

    def public_serialize_deserialize(self, pfcls1, pfcls2, frag_index,
                                     frag_count, data):
        '''
            test deserialize(serialize()) of frag_cls
        '''
        fr1 = pfcls1(frag_index=frag_index, frag_count=frag_count, data=data)
        #
        # pfcls2 is partial, therefore .func
        #
        fr2 = pfcls2().deserialize(fr1.serialize())
        assert fr1._packet_id == fr2._packet_id
        assert frag_index == fr1._frag_index == fr2._frag_index
        assert frag_count == fr1._frag_count == fr2._frag_count
        assert data == fr1.data == fr2.data

    def multi_public_serialize_deserialize(self, pfcls1, pfcls2):
        '''
            test deserialize(serialize()) of frag_cls with:
            * zero-length data
            * one byte length data
            * 100 random data lengths between 0 and 1024
        '''
        frag_index = random.randint(0, 100)
        frag_count = random.randint(frag_index + 1, frag_index + 100)
        datalist = ['']
        datalist += ['a']
        datalist += [nacl.public.random(random.randint(0, 4096))
                     for i in xrange(100)]
        for data in datalist:
            self.public_serialize_deserialize(pfcls1, pfcls2, frag_index,
                                              frag_count, data)


class Test_PublicFragment(unittest.TestCase, MyTestMixin):

    def do_test_cls(self, cls, **kw):
        k1 = nacl.public.PrivateKey.generate()
        k2 = nacl.public.PrivateKey.generate()
        # f1 = cls(private_key=k1, public_key=k2.public_key)
        # f2 = cls(private_key=k2, public_key=k1.public_key)
        pfcls1 = functools.partial(cls, private_key=k1,
                                   public_key=k2.public_key, **kw)
        pfcls2 = functools.partial(cls, private_key=k2,
                                   public_key=k1.public_key, **kw)
        self.multi_public_serialize_deserialize(pfcls1, pfcls2)

    def test_various_classes(self):
        self.do_test_cls(PublicFragment)
        self.do_test_cls(DnsPublicFragment, tld='.asdqwe.com')

    def test2(self):
        self.serialize_deserialize(Fragment, frag_index=3, frag_count=4,
                                   data='asdqwe')
        self.multi_serialize_deserialize(Fragment)


class Test_Fragment(unittest.TestCase):

    def test1(self):
        frag_index = 4
        frag_count = 7
        data = 'foobar'
        fr1 = Fragment(frag_index=frag_index, frag_count=frag_count, data=data)
        fr2 = fr1.deserialize(fr1.serialize())
        assert fr1._packet_id == fr2._packet_id
        assert frag_index == fr1._frag_index == fr2._frag_index
        assert frag_count == fr1._frag_count == fr2._frag_count
        assert data == fr1.data == fr2.data


if __name__ == '__main__':
    if sys.argv[1] == '--test':
        del sys.argv[1]
        import unittest
        unittest.main()
    else:
        sys.exit(main(*sys.argv[1:]))
