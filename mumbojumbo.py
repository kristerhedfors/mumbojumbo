#!/usr/bin/env python
# -*- coding: utf-8 -*-
#
# known attacks:
#  replay (no timestamp)
#  hmac shared secret issues
#
import sys
import logging
import subprocess
import multiprocessing
import socket
import time
import os
import hmac
import hashlib
import Queue
import re
import base64


logging.basicConfig(level=logging.DEBUG)
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

    def __init__(self):
        self._packets = {}
        self._missing_count = {}
        self.outq = Queue.Queue()

    def gen_chunks(self, data):
        encoded = b32enc(data)
        chunks = split2len(encoded, 32)
        return chunks

    def encrypt(self, plaintext):
        cmd = 'gpg -e --recipient krister@sometld.xy -e --yes'.split()
        p = subprocess.Popen(cmd, stdin=subprocess.PIPE,
                             stdout=subprocess.PIPE)
        p.stdin.write(plaintext)
        p.stdin.flush()
        p.stdin.close()
        ciphertext = p.stdout.read()
        p.wait()
        return ciphertext

    def decrypt(self, ciphertext):
        cmd = 'gpg -e --recipient krister@sometld.xy -e --yes'.split()
        p = subprocess.Popen(cmd, stdin=subprocess.PIPE,
                             stdout=subprocess.PIPE)
        p.stdin.write(ciphertext)
        p.stdin.flush()
        p.stdin.close()
        plaintext = p.stdout.read()
        p.wait()
        return plaintext

    def get_uniq_id(self):
        return os.urandom(6).encode('hex')

    def calc_checksum(self, msg):
        h = hmac.new(self._hmac_key, msg=msg, digestmod=hashlib.sha256)
        return h.hexdigest()[:12]

    def verify_checksum(self, msg, checksum):
        assert self.calc_checksum(msg) == checksum

    def split(self, data, tld=tld):
        lst = []
        uniq_id = self.get_uniq_id()
        chunks = self.gen_chunks(data)
        for (i, chunk) in enumerate(chunks):
            h = self.build_data_packet(uniq_id, i, chunk, tld)
            lst.append(h)
        count = len(lst)
        h = self.build_start_packet(uniq_id, count, tld)
        lst.insert(0, h)
        return lst

    def build_data_packet(self, uniq_id, i, chunk, tld):
        h = 'd-{0}-{1}-{2}-{3}{4}'.format(uniq_id, i, chunk, '', tld)
        checksum = self.calc_checksum(h)
        h = 'd-{0}-{1}-{2}-{3}{4}'.format(uniq_id, i, chunk, checksum, tld)
        return h

    def build_start_packet(self, uniq_id, count, tld):
        h = 's-{0}-{1}-{2}{3}'.format(uniq_id, count, '', tld)
        checksum = self.calc_checksum(h)
        h = 's-{0}-{1}-{2}{3}'.format(uniq_id, count, checksum, tld)
        return h

    def parse_packet(self, h, tld=tld):
        _h = h
        if not h.endswith(tld):
            return
        h = h[:-len(tld)]
        if h.startswith('s-'):
            logger.debug('S packet')
            h = h[2:]
            (uniq_id, count, checksum) = h.split('-')
            self.verify_checksum(_h.replace(checksum, ''), checksum)
            count = int(count)
            logger.debug('asserting')
            assert count <= self._max_count
            self._packets[uniq_id] = [None] * count
            self._missing_count[uniq_id] = count
            logger.debug('S packet done')
        elif h.startswith('d-'):
            h = h[2:]
            (uniq_id, idx, chunk, checksum) = h.split('-')
            self.verify_checksum(_h.replace(checksum, ''), checksum)
            idx = int(idx)
            if uniq_id in self._packets:
                if self._packets[uniq_id][idx] is None:
                    self._packets[uniq_id][idx] = chunk
                    self._missing_count[uniq_id] -= 1
                if self._missing_count[uniq_id] == 0:
                    self.finalize(uniq_id)

    def finalize(self, uniq_id):
        b32buf = ''.join(self._packets[uniq_id])
        buf = b32dec(b32buf)
        self.outq.put(buf)
        del self._packets[uniq_id]
        del self._missing_count[uniq_id]


def ping_hosts(hosts):
    plist = []
    for host in hosts:
        cmd = 'ping -c1 -w1 {0}'.format(host)
        time.sleep(0.1)
        p = subprocess.Popen(cmd.split())
    for p in plist:
        p.wait()


def main(*args):
    mj = Mumbojumbo()

    if args[0] == '--server':
        cmd = 'tshark -li eth0 -T fields -e dns.qry.name udp port 53'
        p = subprocess.Popen(cmd.split(), stdout=subprocess.PIPE)
        line = p.stdout.readline().strip()
        while line:
            logger.debug('parsing ' + line)
            mj.parse_packet(line)
            if not mj.outq.empty():
                packet = mj.outq.get()
                print 'Got packet:', repr(packet)
            logger.debug('reading next query...')
            line = p.stdout.readline().strip()
        p.wait()
        sys.exit()

    elif args[0] == '--client':
        chunks = mj.split('aaaaaaaaaabbbbbbccccccccdddddddeeeeeeeeffffff')
        print '\n'.join(chunks)
        ping_hosts(chunks)


if __name__ == '__main__':
    sys.exit(main(*sys.argv[1:]))

