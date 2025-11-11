#!/usr/bin/env python3
"""DNS query utilities for testing."""

import logging
import subprocess

import nacl.public

logger = logging.getLogger(__name__)


class DnsQueryReader:
    """Read DNS queries from network using tshark."""

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


class DnsQueryWriter:
    """Build and send DNS queries."""

    DEFAULT_ADDR = ('127.0.0.1', 53)

    def __init__(self, name_server=DEFAULT_ADDR):
        if type(name_server) is str:
            name_server = (name_server, 53)
        self._name_server = name_server

    def _get_socket(self):
        from socket import socket, AF_INET, SOCK_DGRAM
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
