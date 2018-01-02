#!/usr/bin/env python3
#
# Copyright (c) 2017 John Newbery
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
from codecs import encode
import copy
from enum import Enum
import time

from serialize import SerializationError, BCBytesStream
from util import bytes_to_hex_str, hash256

class BanReason(Enum):
    UNKNOWN = 0
    NODE_MISBEHAVING = 1
    MANUALLY_ADDED = 2

COIN = 10 ** 8

VERSION_HD_CHAIN_SPLIT = 2
VERSION_WITH_HDDATA = 10

class OutPoint():
    def __init__(self, hash=0, n=0):
        self.hash = hash
        self.n = n

    def __repr__(self):
        return "OutPoint(hash=%064x n=%i)" % (self.hash, self.n)

    def deserialize(self, f):
        self.hash = f.deser_uint256()
        self.n = f.deser_uint32()

    def serialize(self, f):
        f.ser_uint256(self.hash)
        f.ser_uint32(self.n)

class TxIn():
    def __init__(self, outpoint=None, script_sig=b"", sequence=0):
        if outpoint is None:
            self.prevout = OutPoint()
        else:
            self.prevout = outpoint
        self.script_sig = script_sig
        self.sequence = sequence

    def __repr__(self):
        return "TxIn(prevout=%s script_sig=%s sequence=%i)" \
            % (repr(self.prevout), bytes_to_hex_str(self.script_sig),
               self.sequence)

    def deserialize(self, f):
        self.prevout = OutPoint()
        self.prevout.deserialize(f)
        self.script_sig = f.read(f.deser_compact_size())
        self.sequence = f.deser_uint32()

    def serialize(self, f):
        self.prevout.serialize(f)
        f.ser_string(self.script_sig)
        f.ser_uint32(self.sequence)

class TxOut():
    def __init__(self, value=0, script_pub_key=b""):
        self.value = value
        self.script_pub_key = script_pub_key

    def __repr__(self):
        return "TxOut(value=%i.%08i script_pub_key=%s)" \
            % (self.value // COIN, self.value % COIN,
               bytes_to_hex_str(self.script_pub_key))

    def deserialize(self, f):
        self.value = f.deser_int64()
        self.script_pub_key = f.read(f.deser_compact_size())

    def serialize(self, f):
        f.ser_int64(self.value)
        f.ser_string(self.script_pub_key)

class ScriptWitness():
    def __init__(self):
        # stack is a vector of strings
        self.stack = []

    def __repr__(self):
        return "ScriptWitness(%s)" % \
               (",".join([x for x in self.stack]))

    def is_null(self):
        if self.stack:
            return False
        return True

class TxInWitness():
    def __init__(self):
        self.scriptWitness = ScriptWitness()

    def __repr__(self):
        return repr(self.scriptWitness)

    def deserialize(self, f):
        self.scriptWitness.stack = f.deser_string_vector()

    def serialize(self, f):
        f.ser_string_vector(self.scriptWitness.stack)

    def is_null(self):
        return self.scriptWitness.is_null()

class TxWitness():
    def __init__(self):
        self.vtxinwit = []

    def __repr__(self):
        return "TxWitness(%s)" % \
               (';'.join([repr(x) for x in self.vtxinwit]))

    def deserialize(self, f):
        for i in range(len(self.vtxinwit)):
            self.vtxinwit[i].deserialize(f)

    def serialize(self, f):
        # This is different than the usual vector serialization --
        # we omit the length of the vector, which is required to be
        # the same length as the transaction's vin vector.
        for x in self.vtxinwit:
            x.serialize(f)

    def is_null(self):
        for x in self.vtxinwit:
            if not x.is_null():
                return False
        return True

class Transaction():
    def __init__(self, tx=None):
        if tx is None:
            self.version = 1
            self.vin = []
            self.vout = []
            self.wit = TxWitness()
            self.nLockTime = 0
            self.sha256 = None
            self.hash = None
        else:
            self.version = tx.version
            self.vin = copy.deepcopy(tx.vin)
            self.vout = copy.deepcopy(tx.vout)
            self.nLockTime = tx.nLockTime
            self.sha256 = tx.sha256
            self.hash = tx.hash
            self.wit = copy.deepcopy(tx.wit)

    def __repr__(self):
        return "txid: {}, version: {}, no_txins: {}, no_txouts: {}, nLockTime: {}".format(self.txid, self.version, len(self.vin), len(self.vout), self.nLockTime)

    def deserialize(self, f):
        self.version = f.deser_int32()
        segwit = False
        if int.from_bytes(f.peep_byte(), 'big') == 0:
            if int.from_bytes(f.read(2), 'big') != 1:
                raise SerializationError("Segwit flag not set to 1")
            segwit = True
        self.vin = f.deser_vector(TxIn)
        self.vout = f.deser_vector(TxOut)
        if segwit:
            self.wit.vtxinwit = [TxInWitness() for i in range(len(self.vin))]
            self.wit.deserialize(f)
        self.nLockTime = f.deser_uint32()
        self.sha256 = None
        self.hash = None

    def serialize(self, f, with_witness=True):
        flags = 0
        if not self.wit.is_null():
            flags |= 1
        f.ser_int32(self.version)
        if flags:
            dummy = []
            f.ser_vector(dummy)
            f.ser_uint8(flags)
        f.ser_vector(self.vin, 'serialize')
        f.ser_vector(self.vout, 'serialize')
        if (flags & 1) and with_witness:
            if (len(self.wit.vtxinwit) != len(self.vin)):
                # vtxinwit must have the same length as vin
                self.wit.vtxinwit = self.wit.vtxinwit[:len(self.vin)]
                for i in range(len(self.wit.vtxinwit), len(self.vin)):
                    self.wit.vtxinwit.append(TxInWitness())
            self.wit.serialize(f)
        f.ser_uint32(self.nLockTime)

    @property
    def txid(self):
        f = BCBytesStream()
        self.serialize(f, False)
        return encode(hash256(f.getvalue())[::-1], 'hex_codec').decode('ascii')

class MerkleTransaction(Transaction):
    def __init__(self):
        super().__init__()
        self.hash_block = 0
        self.merkle_branch = b''
        self.index = 0

    def deserialize(self, f):
        super().deserialize(f)
        self.hash_block = f.read(32)
        merkle_proof_len = f.deser_compact_size()  # Should be zero!
        self.merkle_branch = f.read(32 * merkle_proof_len)
        self.index = f.deser_int32()

class WalletTransaction(MerkleTransaction):
    def __init__(self):
        super().__init__()
        self.vtxPrev = []
        self.mapValue = {}
        self.order_form = []
        self.time_received_is_tx_time = 0
        self.time_received = 0
        self.from_me = False
        self.spent = False

    def deserialize(self, f):
        super().deserialize(f)
        n_vtx_prev = f.deser_compact_size()  # Should be zero!
        for i in range(n_vtx_prev):
            self.vtxPrev.append(f.parse_merkle_tx())

        n_map_value = f.deser_compact_size()
        for i in range(n_map_value):
            key = f.deser_string()
            value = f.deser_string()
            self.mapValue[key] = value
        n_order_form = f.deser_compact_size()
        for i in range(n_order_form):
            first = f.deser_string()
            second = f.deser_string()
            self.order_form.append((first, second))
        self.time_received_is_tx_time = f.deser_uint32()
        self.time_received = f.deser_uint32()
        self.from_me = f.deser_boolean()
        self.spent = f.deser_boolean()

class Address():
    def __init__(self):
        self.version = 0
        self.time = 0
        self.services = 0
        self.ip = b''
        self.port = 0

    def __repr__(self):
        if self.ipv4:
            ret = ".".join([str(int.from_bytes(self.ip[n:n + 1], 'big')) for n in range(12, 16)])
        else:
            ret = ":".join([self.ip[n:n + 1].hex() for n in range(16)])

        ret += ", port: {}".format(self.port)

        return ret

    def deserialize(self, f):
        self.version = f.deser_uint32()
        self.time = f.deser_uint32()
        self.services = f.deser_uint64()
        self.ip = f.read(16)
        self.port = f.deser_uint16(big=True)

        if int.from_bytes(self.ip[0:12], 'big') == 0xffff:
            self.ipv4 = True
        else:
            self.ipv4 = False

class AddrInfo():
    def __init__(self):
        self.address = Address()
        self.source = b''
        self.last_success = 0
        self.attempts = 0

    def deserialize(self, f):
        self.address.deserialize(f)
        self.source = f.read(16)
        self.last_success = f.deser_int64()
        self.attempts = f.deser_int32()

    def __repr__(self):
        return self.address.__repr__()

class BestBlock():
    def __init__(self):
        self.version = 0
        self.have = []

    def deserialize(self, f):
        self.version = f.deser_uint32()
        for block in range(f.deser_compact_size()):
            self.have.append(f.read(32).hex())

    def __repr__(self):
        if self.have:
            best_block = self.have[0]
        else:
            best_block = "empty"
        return "version:{}, bestblock hash: {}\n".format(self.version, best_block)

class KeyPool():
    """A Keypool Entry."""
    def __init__(self):
        self.version = 0
        self.time = 0
        self.pub_key = b''

    def deserialize(self, f):
        self.version = f.deser_uint32()
        self.time = f.deser_int64()
        self.pub_key = f.read(f.deser_compact_size()).hex()

    def __repr__(self):
        return "version: {}, time: {}, pub_key: 0x{}".format(self.version, time.ctime(self.time), self.pub_key)

class Account():
    """A wallet account."""
    def __init__(self):
        self.version = 0
        self.pub_key = b''

    def deserialize(self, f):
        self.version = f.deser_int32()
        self.pub_key = f.read(f.deser_compact_size()).hex()

    def __repr__(self):
        return "version: {}, pub_key: 0x{}".format(self.version, self.pub_key)

class HDChain():
    """A wallet HD chain."""
    def __init__(self):
        self.version = 0
        self.external_chain_counter = 0
        self.master_key_id = b''
        self.internal_chain_counter = 0

    def deserialize(self, f):
        self.version = f.deser_uint32()
        self.external_chain_counter = f.deser_uint32()
        self.master_key_id = f.read(20).hex()
        if self.version > VERSION_HD_CHAIN_SPLIT:
            self.internal_chain_counter = f.deser_uint32()

    def __repr__(self):
        return "version: {}, master_key_id: {}, external_chain_counter: {}, internal_chain_counter: {}".format(self.version, self.master_key_id, self.external_chain_counter, self.internal_chain_counter)

class AccountingEntry():
    """Accounting entry for internal wallet transfers"""
    def __init__(self):
        self.account = ''
        self.index = 0
        self.version = 0
        self.credit_debit = 0
        self.time = 0
        self.other_account = ''
        self.comment = ''

    def deserialize(self, f):
        self.version = f.read_int32()
        self.credit_debit = f.read_int64()
        self.time = f.read_int64()
        self.other_account = f.deser_string()
        self.comment = f.deser_string()

    def __repr__(self):
        return "version: {}, from_account: {}, index: {}, to_account: {}, credit_debit: {}, time: {}, comment: {}".format(self.version, self.index, self.account, self.other_account, self.credit_debit, time.ctime(self.time), self.comment)

class KeyMeta():
    """Metadata for a wallet key"""
    def __init__(self):
        self.version = 0
        self.create_time = 0
        self.hd_key_path = 'Not HD'
        self.hd_master_key_id = 'Not HD'

    def deserialize(self, f):
        self.version = f.deser_int32()
        self.create_time = f.deser_int64()
        if self.version >= VERSION_WITH_HDDATA:
            self.hd_key_path = f.deser_string()
            self.hd_master_key_id = f.read(20).hex()

    def __repr__(self):
        return "version: {}, create_time: {}, hd_key_path: {}, hd_master_key_id: {}".format(self.version, time.ctime(self.create_time), self.hd_key_path, self.hd_master_key_id)

class Subnet():
    """An IPv4 or IPv6 subnet.

    network: a 16 byte array representing the host or subnet. An IPv4 address is represented by
             10 bytes of 0x00, 2 bytes of 0xff, and 4 bytes of the IP address.
    netmask: the netmask for the subnet."""
    def __init__(self):
        self.network = b''
        self.netmask = b''

    def __repr__(self):
        if self.ipv4:
            ret = ".".join([str(int.from_bytes(self.network[n:n + 1], 'big')) for n in range(12, 16)])
            ret += ", netmask: "
            ret += ".".join([str(int.from_bytes(self.netmask[n:n + 1], 'big')) for n in range(12, 16)])
        else:
            ret = ":".join([self.network[n:n + 1].hex() for n in range(16)])
            ret += ", netmask: "
            ret += ":".join([self.netmask[n:n + 1].hex() for n in range(16)])

        return ret

    def deserialize(self, f):
        self.network = f.read(16)
        self.netmask = f.read(16)
        self.valid = f.deser_boolean()

        if int.from_bytes(self.network[0:12], 'big') == 0xffff:
            self.ipv4 = True
        else:
            self.ipv4 = False

class BanEntry():
    def __init__(self):
        self.version = 0
        self.create_time = 0
        self.ban_until = 0
        self.reason = BanReason.UNKNOWN

    def __repr__(self):
        ret = "version: {}, create_time: {}, ban_until: {}".format(
            self.version,
            time.ctime(self.create_time),
            time.ctime(self.ban_until),
        )
        ret += ", reason: "
        if self.reason == BanReason.UNKNOWN:
            ret += "unknown"
        elif self.reason == BanReason.MANUALLY_ADDED:
            ret += "manually_added"
        elif self.reason == BanReason.NODE_MISBEHAVING:
            ret += "node_misbehaving"

        return ret

    def deserialize(self, f):
        self.version = f.deser_int32()
        self.create_time = f.deser_int64()
        self.ban_until = f.deser_int64()
        self.reason = BanReason(f.deser_int8())

class Ban():
    """A single entry in the banmap"""
    def __init__(self):
        self.subnet = None
        self.ban_entry = None

    def deserialize(self, f):
        """Parse a ban entry from the start of a bytestream. Return a Ban object."""
        self.subnet = Subnet()
        self.subnet.deserialize(f)
        self.ban_entry = BanEntry()
        self.ban_entry.deserialize(f)
