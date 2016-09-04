#!/usr/bin/env python
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
        while line:
            logger.debug('parsing ' + line)
            yield line
            logger.debug('reading next query...')
            line = p.stdout.readline().strip()
        p.wait()

    def __del__(self):
        self._p.terminate()
        self._p.wait()


def test_client(packet_engine, rounds=10):
    name_server = DnsQueryWriter()
    for i in xrange(rounds):
        logger.info('ROUND({0})'.format(i))
        data = nacl.public.random(random.randint(200, 400))
        logger.info('DATA({0}): {1}'.format(len(data), repr(data)))
        datahash = hashlib.sha256(data).digest()
        logger.info('HASH({0}): {1}'.format(len(datahash), repr(datahash)))
        name_server.query_all(packet_engine.to_wire(data))
        time.sleep(0.03)
        name_server.query_all(packet_engine.to_wire(datahash))
        time.sleep(0.03)
    print 'SUCCESS sent {0} packets of random data plus hashes'.format(rounds)


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
        s = ''
        s += nacl.public.random(2)  # query id
        s += '\x01\x00'  # standard query
        s += '\x00\x01'  # queries
        s += '\x00\x00'  # answer rr:s
        s += '\x00\x00'  # authority rr:s
        s += '\x00\x00'  # additional rr:s
        for part in name.split('.'):
            s += chr(len(part))
            s += part
        s += '\x00'
        s += '\x00\x01'  # type: a, host address
        s += '\x00\x01'  # class: in
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
    private_key = nacl.public.PrivateKey(_key.decode('base64'))
    pfcls = DnsPublicFragment.bind(private_key=private_key,
                                   public_key=private_key.public_key)
    packet_engine = PacketEngine(pfcls)
    data = nacl.public.random(1024)

    count = 1024
    lst = []
    t1 = time.time()
    for i in xrange(count):
        for item in packet_engine.to_wire(data):
            lst.append(item)
    t2 = time.time()
    for item in lst:
        packet_engine.from_wire(item)
    t3 = time.time()

    while not packet_engine.packet_outqueue.empty():
        packet_engine.packet_outqueue.get()
        count -= 1
    assert count == 0

    print 'Offline processing of 1024 messages, 1024 bytes per message:'
    print 'send time: {0:.2f}s'.format(t2 - t1)
    print 'recv time: {0:.2f}s'.format(t3 - t2)
    print 'message fragment count:', len(lst)


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
        pfcls1 = cls.bind(private_key=k1, public_key=k2.public_key, **kw)
        pfcls2 = cls.bind(private_key=k2, public_key=k1.public_key, **kw)
        self.multi_public_serialize_deserialize(pfcls1, pfcls2)

    def test_classes(self):
        self.do_test_cls(PublicFragment)
        self.do_test_cls(DnsPublicFragment, domain='.asdqwe.com')

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
        pfcls1 = DnsPublicFragment.bind(private_key=k1,
                                        public_key=k2.public_key)
        pfcls2 = DnsPublicFragment.bind(private_key=k2,
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


def main(*args):
    _pk1 = 'nQV+KhrNM2kbJGCrm+LlfPfiCodLV9A4Ldok4f6gvD4='
    _pk2 = 'DGor3Mkdy8Txp4bRMPYURduV7fVXcUCNnaFra1RIums='
    pk1 = nacl.public.PrivateKey(_pk1.decode('base64'))
    pk2 = nacl.public.PrivateKey(_pk2.decode('base64'))

    pfcls_client = DnsPublicFragment.bind(private_key=pk1,
                                          public_key=pk2.public_key)
    packet_engine_client = PacketEngine(pfcls_client)

    pfcls_server = DnsPublicFragment.bind(private_key=pk2,
                                          public_key=pk1.public_key)

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
