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


class BaseFragment(object):

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
            u32 packet_id
            u16 frag_index
            u16 frag_count
            u16 len(frag_data)
            bytes frag_data
    '''

    def deserialize(self, raw):
        packet_id = struct.unpack('I', raw[:4])[0]
        frag_index = struct.unpack('H', raw[4:6])[0]
        frag_count = struct.unpack('H', raw[6:8])[0]
        frag_data_len = struct.unpack('H', raw[8:10])[0]
        frag_data = raw[10:]
        assert frag_data_len == len(frag_data)
        assert 1 <= frag_count
        assert frag_index < frag_count
        return self.__class__(packet_id=packet_id, frag_index=frag_index,
                              frag_count=frag_count, frag_data=frag_data)

    #
    # __init__
    #
    def __init__(self, packet_id=None, frag_index=0, frag_count=1, **kw):
        self._packet_id = packet_id or PacketEngine.gen_packet_id()
        self._frag_index = frag_index
        self._frag_count = frag_count
        super(Fragment, self).__init__(**kw)

    def serialize(self):
        ser = ''
        ser += struct.pack('I', self._packet_id)
        ser += struct.pack('H', self._frag_index)
        ser += struct.pack('H', self._frag_count)
        ser += struct.pack('H', len(self._frag_data))
        ser += self._frag_data
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
    if s == '':
        return ['']

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
    DEFAULT_TLD = '.sometld.xy'

    def __init__(self, tld=DEFAULT_TLD, **kw):
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

    @classmethod
    def gen_packet_id(cls):
        return struct.unpack('I', nacl.public.random(4))[0]

    def __init__(self, frag_cls=None, max_frag_data_len=None):
        self._frag_cls = frag_cls
        self._max_frag_data_len = max_frag_data_len
        self._packet_assembly = {}
        self._packet_assembly_counter = {}
        self._packet_outqueue = Queue.Queue()

    @property
    def packet_outqueue(self):
        return self._packet_outqueue

    def to_wire(self, packet_data):
        '''
            Generator yielding zero or more fragments from data.
        '''
        packet_id = self.__class__.gen_packet_id()
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
            Returns packet if wire_data constitutes final missing fragment
            of a packet, otherwise None.
        '''
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
                print 'ERR _frag_count mismatch'
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
                    raise Exception('error: counter < 0')
                if counter[packet_id] == 0:
                    #
                    # final fragment obtained, return packet
                    #
                    self._finalize_packet(packet_id)

    def _finalize_packet(self, packet_id):
        frag_data_lst = self._packet_assembly[packet_id]
        packet_data = ''.join(frag_data_lst)
        self.packet_outqueue.put(packet_data)


def main(*args):

    if args[0] == '--test-server':
        test_server(rounds=100)
        sys.exit()

    elif args[0] == '--test-client':
        test_client(rounds=100)
        sys.exit()


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
        datalist = ['']
        datalist += ['a']
        datalist += [os.urandom(random.randint(0, 4096)) for i in xrange(100)]
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
        datalist = ['']
        datalist += ['a']
        datalist += [nacl.public.random(random.randint(0, 4096))
                     for i in xrange(100)]
        for data in datalist:
            self.public_serialize_deserialize(pfcls1, pfcls2, frag_index,
                                              frag_count, data)


class Test_Fragment(unittest.TestCase):

    def test1(self):
        frag_index = 4
        frag_count = 7
        frag_data = 'foobar'
        fr1 = Fragment(frag_index=frag_index, frag_count=frag_count,
                       frag_data=frag_data)
        fr2 = fr1.deserialize(fr1.serialize())
        assert fr1._packet_id == fr2._packet_id
        assert frag_index == fr1._frag_index == fr2._frag_index
        assert frag_count == fr1._frag_count == fr2._frag_count
        assert frag_data == fr1.frag_data == fr2.frag_data


class Test_PublicFragment(unittest.TestCase, MyTestMixin):

    def do_test_cls(self, cls, **kw):
        k1 = nacl.public.PrivateKey.generate()
        k2 = nacl.public.PrivateKey.generate()
        pfcls1 = functools.partial(cls, private_key=k1,
                                   public_key=k2.public_key, **kw)
        pfcls2 = functools.partial(cls, private_key=k2,
                                   public_key=k1.public_key, **kw)
        self.multi_public_serialize_deserialize(pfcls1, pfcls2)

    def test_classes(self):
        self.do_test_cls(PublicFragment)
        self.do_test_cls(DnsPublicFragment, tld='.asdqwe.com')

    def test2(self):
        self.serialize_deserialize(Fragment, frag_index=3, frag_count=4,
                                   frag_data='asdqwe')
        self.multi_serialize_deserialize(Fragment)


class Test_PacketEngine(unittest.TestCase, MyTestMixin):

    def setUp(self):
        packet_data_lst = ['']
        packet_data_lst += ['a']
        packet_data_lst += [nacl.public.random(random.randint(1, 2048))
                            for i in xrange(64)]
        k1 = nacl.public.PrivateKey.generate()
        k2 = nacl.public.PrivateKey.generate()
        pfcls1 = functools.partial(DnsPublicFragment, private_key=k1,
                                   public_key=k2.public_key)
        pfcls2 = functools.partial(DnsPublicFragment, private_key=k2,
                                   public_key=k1.public_key)
        self.packet_data_lst = packet_data_lst
        self.pfcls1 = pfcls1
        self.pfcls2 = pfcls2

    def do_test_cls(self, cls, **kw):
        pe1 = PacketEngine(frag_cls=self.pfcls1, **kw)
        pe2 = PacketEngine(frag_cls=self.pfcls2, **kw)
        for packet_data in self.packet_data_lst:
            for wire_data in pe1.to_wire(packet_data=packet_data):
                pe2.from_wire(wire_data=wire_data)
            out_data = pe2.packet_outqueue.get()
            assert packet_data == out_data
            assert pe2.packet_outqueue.empty()

    def test_classes(self):
        self.do_test_cls(PacketEngine, max_frag_data_len=100)


if __name__ == '__main__':
    if sys.argv[1] == '--test':
        del sys.argv[1]
        import unittest
        unittest.main()
    else:
        sys.exit(main(*sys.argv[1:]))
