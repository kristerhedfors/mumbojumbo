#!/usr/bin/env python3
"""Helper functions for testing."""

import hashlib
import logging
import os
import random
import subprocess
import time

import nacl.public

from .dns_utils import DnsQueryReader, DnsQueryWriter

logger = logging.getLogger(__name__)


def ping_hosts(hosts):
    """Ping multiple hosts in parallel."""
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


def test_client(packet_engine, rounds=10):
    """Test client: send random packets."""
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
    """Test server: receive and validate packets."""
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


def test_dns_query():
    """Test basic DNS queries."""
    name_server = DnsQueryWriter()
    names = 'www.dn.se www.kernel.org whatever.asdqwe.com'.split()
    name_server.query_all(names)


def test_performance():
    """Performance benchmark for encryption/decryption."""
    from mumbojumbo import DnsPublicFragment, PacketEngine
    import base64

    _key = r'nQV+KhrNM2kbJGCrm+LlfPfiCodLV9A4Ldok4f6gvD4='
    private_key = nacl.public.PrivateKey(base64.b64decode(_key))
    # For SealedBox: client uses client_key only, server uses server_key only
    pfcls_encrypt = DnsPublicFragment.bind(client_key=private_key.public_key)
    pfcls_decrypt = DnsPublicFragment.bind(server_key=private_key)
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
