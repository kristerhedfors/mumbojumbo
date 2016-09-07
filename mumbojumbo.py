#!/usr/bin/env python
#
# Copyright (c) 2016, Krister Hedfors
# All rights reserved.
#
# Redistribution and use in source and binary forms, with or without
# modification, are permitted provided that the following conditions are met:
#
# * Redistributions of source code must retain the above copyright notice, this
#  list of conditions and the following disclaimer.
#
# * Redistributions in binary form must reproduce the above copyright notice,
#  this list of conditions and the following disclaimer in the documentation
#  and/or other materials provided with the distribution.
#
# THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
# AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
# IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
# DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE
# FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
# DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
# SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
# CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY,
# OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
# OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
#
#
# Enough with that..
#
# This is an implementation of the Mumbojumbo protocol. Essentially NaCL
# public key encrypted (currently) one way communication over DNS.
#
# Requirements:
#   * The python package `pynacl`,
#   * ability to run `tshark` for DNS packet capturing,
#   * a Mumbojumbo client,
#   * a reason for using Mumbojumbo(!)
#
# TODO:
#   * make starttls and auth for SMTP optional through config
#   * multiple SMTP recipients
#   * handle --loglevel correctly
#
import base64
import functools
import logging
import Queue
import socket
import struct
import subprocess
import sys
import optparse
import ConfigParser
import traceback
import smtplib
import hashlib
import hmac
import getpass
# from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText

import nacl.public
import nacl.secret


# logging.basicConfig(level=logging.INFO)
logging.basicConfig(level=logging.DEBUG)
global logger
logger = logging.getLogger(__name__)


def b32enc(s):
    return base64.b32encode(s).replace('=', '')


def b32dec(s):
    r = len(s) % 8
    if r:
        s += '=' * (8 - r)
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
            u32 packet_id
            u16 frag_index
            u16 frag_count
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

    def _unpack_ntohl(self, s):
        assert len(s) == 4
        nval = struct.unpack('I', s)[0]
        return socket.ntohl(nval)

    def _unpack_ntohs(self, s):
        assert len(s) == 2
        nval = struct.unpack('H', s)[0]
        return socket.ntohs(nval)

    def serialize(self):
        ser = ''
        ser += self._htonl_pack(self._packet_id)
        ser += self._htons_pack(self._frag_index)
        ser += self._htons_pack(self._frag_count)
        ser += self._htons_pack(len(self._frag_data))
        ser += self._frag_data
        return ser

    def deserialize(self, raw):
        packet_id = self._unpack_ntohl(raw[:4])
        frag_index = self._unpack_ntohs(raw[4:6])
        frag_count = self._unpack_ntohs(raw[6:8])
        frag_data_len = self._unpack_ntohs(raw[8:10])
        frag_data = raw[10:]
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
        return self.__class__(packet_id=packet_id, frag_index=frag_index,
                              frag_count=frag_count, frag_data=frag_data)


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
        plaintext = ''
        try:
            plaintext = self._box.decrypt(ciphertext=ciphertext)
        except:
            logger.debug('decrypt exception:' + traceback.format_exc())
            raise
        logger.debug('decrypted {0} bytes of data'.format(len(plaintext)))
        logger.debug('{0}'.format(repr(plaintext)))
        return super(PublicFragment, self).deserialize(plaintext)


def _split2len(s, n):
    assert n > 0
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
    DEFAULT_TLD = '.xyxyx.xy'

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
        return base64.b32encode(s).replace('=', '').lower()

    def _b32dec(self, s):
        s = s.upper()
        r = len(s) % 8
        if r:
            s += '=' * (8 - r)
        return base64.b32decode(s)


class PacketEngine(object):

    MAX_FRAG_DATA_LEN = 100  # make dynamic

    @classmethod
    def gen_packet_id(cls):
        return struct.unpack('I', nacl.public.random(4))[0]

    def __init__(self, frag_cls=None, max_frag_data_len=MAX_FRAG_DATA_LEN):
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
        logger.debug('to_wire() len(packet_data)==' + str(len(packet_data)))
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
        frag_data_lst = self._packet_assembly[packet_id]
        packet_data = ''.join(frag_data_lst)
        self.packet_outqueue.put(packet_data)


class DnsQueryReader(object):
    '''
        Use tshark to generate DNS queries.
    '''
    TSHARK = '/usr/bin/tshark'

    def __init__(self, iff='', domain=''):
        self._iff = iff
        self._domain = domain

    def __iter__(self):
        cmd = self.TSHARK
        cmd += ' -li eth0 -T fields -e dns.qry.name -- udp port 53'
        self._p = p = subprocess.Popen(cmd.split(), stdout=subprocess.PIPE)
        name = p.stdout.readline().strip()
        while name:
            logger.debug('parsing ' + name)
            if not self._domain or name.lower().endswith(self._domain):
                yield name
            logger.debug('reading next query...')
            name = p.stdout.readline().strip()
        p.wait()

    def __del__(self):
        self._p.terminate()
        self._p.wait()


__usage__ = '''
$ python mumbojumbo.py [options]
'''


__config_skel__ = '''\
#
# !! remember to `chmod 0600` this file !!
#
# for use on client-side:
#   client_privkey={client_privkey}
#   server_pubkey={server_pubkey}
#

[main]
domain = .xyxyx.xy  # including leading dot
network-interface = eth0
client-pubkey = {client_pubkey}
server-privkey = {server_privkey}

[smtp]
server = 127.0.0.1
port = 587
username = someuser
encrypted-password = [create using `python mumbojumbo.py --encrypt`]
from = someuser@somehost.xy
to = otheruser@otherhost.xy
'''


def option_parser():
    p = optparse.OptionParser(usage=__usage__)
    p.add_option('-c', '--config', metavar='path',
                 help='use this config file')
    p.add_option('', '--gen-keys', action='store_true',
                 help='generate and print two NaCL key pairs')
    p.add_option('', '--gen-config-skel', action='store_true',
                 help='print config skeleton file')
    p.add_option('', '--encrypt', action='store_true',
                 help='encrypt some value using a NaCL secret key')
    # p.add_option('', '--decrypt', metavar='val',
    #              help='decrypt `val` using a NaCL secret key')
    # p.add_option('-L', '--loglevel', metavar='INFO|DEBUG|..',
    #              help='set debug log level')
    # p.add_option('-v', '--verbose', action='count', help='increase verbosity')
    return p


def get_nacl_keypair_base64():
    private_key = nacl.public.PrivateKey.generate()
    priv = private_key.encode().encode('base64').strip()
    pub = private_key.public_key.encode().encode('base64').strip()
    return (priv, pub)


class SMTPForwarder(object):

    def __init__(self, server='', port='', from_='', to='',
                 username=None, password=None):
        self._server = server
        self._port = port
        self._from = from_
        self._to = to
        self._username = username
        self._password = password

    def sendmail(self, subject='', text='', charset='utf-8'):
        msg = MIMEText(text)  # utf8 haer med?
        msg.set_charset(charset)
        msg['Subject'] = subject
        msg['From'] = self._from
        msg['To'] = self._to
        smtp = smtplib.SMTP(self._server, port=self._port)
        smtp.ehlo_or_helo_if_needed()
        smtp.starttls()
        if self._username or self._password:
            smtp.login(self._username, self._password)
        smtp.sendmail(self._from, [self._to], msg.as_string())
        smtp.quit()


class SecretBox(nacl.secret.SecretBox):
    '''
        "extended" to use passwords (usually weak),
        by means of simple HMACSHA256 key expansion.
    '''
    def __init__(self, key, *args, **kw):
        key = self.expand(key, 1984)
        super(SecretBox, self).__init__(key, *args, **kw)

    def _expand(self, origkey, key):
        h = hmac.HMAC(key=key, msg=origkey, digestmod=hashlib.sha256)
        return h.digest()

    def expand(self, key, count):
        origkey = key
        for _ in xrange(count):
            key = self._expand(origkey, key)
        return key


def main():
    global logger
    (opt, args) = option_parser().parse_args()

    # if opt.loglevel:
    #     global logger
    #     level = getattr(logging, opt.loglevel.upper())
    #     logging.basicConfig(level=level)
    #     logger = logging.getLogger(__name__)

    if opt.gen_config_skel:
        (client_privkey, client_pubkey) = get_nacl_keypair_base64()
        (server_privkey, server_pubkey) = get_nacl_keypair_base64()
        print __config_skel__.format(
            client_privkey=client_privkey,
            client_pubkey=client_pubkey,
            server_privkey=server_privkey,
            server_pubkey=server_pubkey
        )
        sys.exit()

    if opt.gen_keys:
        (priv, pub) = get_nacl_keypair_base64()
        print priv
        print pub
        sys.exit()

    if opt.encrypt:
        key = getpass.getpass('enter encryption key:')
        key2 = getpass.getpass('enter encryption key again:')
        assert key == key2
        secret = getpass.getpass('enter secret value:')
        secret2 = getpass.getpass('enter secret value again:')
        assert secret == secret2
        del key2
        del secret2
        nonce = nacl.utils.random(24)
        encval = SecretBox(key).encrypt(secret, nonce)
        print ''
        print 'This is your secret value encrypted using your symmetric key:'
        print encval.encode('base64').strip()
        sys.exit()

    if not opt.config:
        print 'Error: No config file specified; you can generate one using',
        print '--gen-config-skel.'
        sys.exit(1)

    config = ConfigParser.SafeConfigParser()
    config.read(opt.config)

    #
    # parse NaCL keys
    #
    server_privkey = nacl.public.PrivateKey(
        config.get('main', 'server-privkey').decode('base64')
    )
    client_pubkey = nacl.public.PublicKey(
        config.get('main', 'client-pubkey').decode('base64')
    )
    domain = config.get('main', 'domain')
    network_interface = config.get('main', 'network-interface')

    logger.info('domain={0}, network_interface={1}'.format(
        domain, network_interface))

    #
    # SMTP forwarding of data?
    #
    smtp_forwarder = None
    smtp_items = config.items('smtp')
    smtp_items = dict(smtp_items)
    if smtp_items:
        key = getpass.getpass('Enter SMTP password decryption key:')
        password = SecretBox(key).decrypt(
            smtp_items['encrypted-password'].decode('base64')
        )
        smtp_forwarder = SMTPForwarder(
            server=smtp_items['server'],
            port=smtp_items['port'],
            from_=smtp_items['from'],
            to=smtp_items['to'],
            username=smtp_items['username'],
            password=password)
        # smtp_forwarder.sendmail('test', 'testtest')

    #
    # prepare packet fragment class
    #
    pf_cls = DnsPublicFragment.bind(domain=domain,
                                    private_key=server_privkey,
                                    public_key=client_pubkey)
    #
    # build packet engine based on fragment class
    #
    packet_engine = PacketEngine(pf_cls)

    #
    # initiate DNS query reader for queries under domain
    #
    dns_query_reader = DnsQueryReader(iff=network_interface, domain=domain)

    #
    # iterate sniffed DNS queries do domain;
    # start to decrypt, parse and reassemble fragments
    # into complete packets
    #
    for name in dns_query_reader:
        logger.debug('DNS query for: ' + name)
        try:
            packet_engine.from_wire(name)
        except:
            msg = 'exception in from_wire(): '
            msg += traceback.format_exc()
            logger.info(msg)
            continue
        if not packet_engine.packet_outqueue.empty():
            data = packet_engine.packet_outqueue.get()
            if smtp_forwarder:
                logger.info('sending email')
                logger.debug('email contents:' + data)
                smtp_forwarder.sendmail(subject='Hello World!', text=data)
            else:
                print 'GET:', packet_engine.packet_outqueue.get()
        sys.stdout.flush()


if __name__ == '__main__':
    sys.exit(main())
