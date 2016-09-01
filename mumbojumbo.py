#  replay (no timestamp)
#  hmac shared secret issues
#
#  b32enc(type + id + countOrIdx [ + data]) + tld
#
import base64
import functools
import logging
import Queue
import socket
import struct
import subprocess
import sys
# import pdb

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
        assert frag_data_len == len(frag_data)
        assert 1 <= frag_count
        assert frag_index < frag_count
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
        plaintext = self._box.decrypt(ciphertext=ciphertext)
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
        logger.debug('DnsPublicFragment: deserialize() enter')
        if dnsname.endswith(self._tld):
            serb32 = dnsname[:-len(self._tld)].replace('.', '')
            ser = self._b32dec(serb32)
            val = super(DnsPublicFragment, self).deserialize(ser)
            if val is None:
                logger.debug('DnsPublicFragment: deserialize() error')
            else:
                logger.debug('DnsPublicFragment: deserialize() success')
            return val
        else:
            msg = 'DnsPublicFragment: deserialize() invalid tld: '
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

    MAX_FRAG_DATA_LEN = 100

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
            Returns packet if wire_data constitutes final missing fragment
            of a packet, otherwise None.
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


class DnsQueryReader(object):
    '''
        Use tshark to generate DNS queries.
    '''
    TSHARK = '/usr/bin/tshark'

    def __init__(self, iff='', domain=''):
        self._iff = iff
        self._domain = domain

    def __iter__(self):
        cmd = self.TSHARK + ' -li eth0 -T fields -e dns.qry.name udp port 53'
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


def main(*args):
    _private_key = r'nQV+KhrNM2kbJGCrm+LlfPfiCodLV9A4Ldok4f6gvD4='
    private_key = nacl.public.PrivateKey(_private_key.decode('base64'))

    pfcls_server = functools.partial(DnsPublicFragment, private_key=private_key)
    packet_engine_server = PacketEngine(pfcls_server)

    dns_query_reader = DnsQueryReader(iff='eth0',
                                      domain='.test.test5.sentorlab.se')
    for name in dns_query_reader:
        print name
        sys.stdout.flush()


if __name__ == '__main__':
    sys.exit(main(*sys.argv[1:]))
