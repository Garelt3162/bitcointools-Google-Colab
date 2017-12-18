#!/usr/bin/env python3
#
# Copyright (c) 2017 John Newbery
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
from codecs import encode
import copy
from enum import Enum
import struct
import time

import deserialize as des
from utils import bytes_to_hex_str, uint256_from_str, hash256

class BanReason(Enum):
    UNKNOWN = 0
    NODE_MISBEHAVING = 1
    MANUALLY_ADDED = 2

COIN = 10 ** 8

class OutPoint():
    def __init__(self, hash=0, n=0):
        self.hash = hash
        self.n = n

    def deserialize(self, f):
        self.hash = des.deser_uint256(f)
        self.n = des.deser_uint32(f)

    def serialize(self):
        r = b""
        r += des.ser_uint256(self.hash)
        r += des.ser_uint32(self.n)
        return r

    def __repr__(self):
        return "OutPoint(hash=%064x n=%i)" % (self.hash, self.n)

class TxIn():
    def __init__(self, outpoint=None, script_sig=b"", sequence=0):
        if outpoint is None:
            self.prevout = OutPoint()
        else:
            self.prevout = outpoint
        self.script_sig = script_sig
        self.sequence = sequence

    def deserialize(self, f):
        self.prevout = OutPoint()
        self.prevout.deserialize(f)
        self.script_sig = des.deser_string(f)
        self.sequence = des.deser_uint32(f)

    def serialize(self):
        r = b""
        r += self.prevout.serialize()
        r += des.ser_string(self.script_sig)
        r += des.ser_uint32(self.sequence)
        return r

    def __repr__(self):
        return "TxIn(prevout=%s script_sig=%s sequence=%i)" \
            % (repr(self.prevout), bytes_to_hex_str(self.script_sig),
               self.sequence)

class TxOut():
    def __init__(self, value=0, script_pub_key=b""):
        self.value = value
        self.script_pub_key = script_pub_key

    def deserialize(self, f):
        self.value = des.deser_int64(f)
        self.script_pub_key = des.deser_string(f)

    def serialize(self):
        r = b""
        r += des.ser_int64(self.value)
        r += des.ser_string(self.script_pub_key)
        return r

    def __repr__(self):
        return "TxOut(value=%i.%08i script_pub_key=%s)" \
            % (self.value // COIN, self.value % COIN,
               bytes_to_hex_str(self.script_pub_key))

class ScriptWitness():
    def __init__(self):
        # stack is a vector of strings
        self.stack = []

    def __repr__(self):
        return "ScriptWitness(%s)" % \
               (",".join([bytes_to_hex_str(x) for x in self.stack]))

    def is_null(self):
        if self.stack:
            return False
        return True

class TxInWitness():
    def __init__(self):
        self.scriptWitness = ScriptWitness()

    def deserialize(self, f):
        self.scriptWitness.stack = des.deser_string_vector(f)

    def serialize(self):
        return des.ser_string_vector(self.scriptWitness.stack)

    def __repr__(self):
        return repr(self.scriptWitness)

    def is_null(self):
        return self.scriptWitness.is_null()

class TxWitness():
    def __init__(self):
        self.vtxinwit = []

    def deserialize(self, f):
        for i in range(len(self.vtxinwit)):
            self.vtxinwit[i].deserialize(f)

    def serialize(self):
        r = b""
        # This is different than the usual vector serialization --
        # we omit the length of the vector, which is required to be
        # the same length as the transaction's vin vector.
        for x in self.vtxinwit:
            r += x.serialize()
        return r

    def __repr__(self):
        return "TxWitness(%s)" % \
               (';'.join([repr(x) for x in self.vtxinwit]))

    def is_null(self):
        for x in self.vtxinwit:
            if not x.is_null():
                return False
        return True

class Transaction():
    def __init__(self, tx=None):
        if tx is None:
            self.nVersion = 1
            self.vin = []
            self.vout = []
            self.wit = TxWitness()
            self.nLockTime = 0
            self.sha256 = None
            self.hash = None
        else:
            self.nVersion = tx.nVersion
            self.vin = copy.deepcopy(tx.vin)
            self.vout = copy.deepcopy(tx.vout)
            self.nLockTime = tx.nLockTime
            self.sha256 = tx.sha256
            self.hash = tx.hash
            self.wit = copy.deepcopy(tx.wit)

    def deserialize(self, f):
        self.nVersion = des.deser_int32(f)
        self.vin = des.deser_vector(f, TxIn)
        flags = 0
        if len(self.vin) == 0:
            flags = des.deser_uint8(f)
            # Not sure why flags can't be zero, but this
            # matches the implementation in bitcoind
            if (flags != 0):
                self.vin = des.deser_vector(f, TxIn)
                self.vout = des.deser_vector(f, TxOut)
        else:
            self.vout = des.deser_vector(f, TxOut)
        if flags != 0:
            self.wit.vtxinwit = [TxInWitness() for i in range(len(self.vin))]
            self.wit.deserialize(f)
        self.nLockTime = des.deser_uint32(f)
        self.sha256 = None
        self.hash = None

    def serialize_without_witness(self):
        r = b""
        r += des.ser_int32(self.nVersion)
        r += des.ser_vector(self.vin)
        r += des.ser_vector(self.vout)
        r += des.ser_uint32(self.nLockTime)
        return r

    # Only serialize with witness when explicitly called for
    def serialize_with_witness(self):
        flags = 0
        if not self.wit.is_null():
            flags |= 1
        r = b""
        r += des.ser_int32(self.nVersion)
        if flags:
            dummy = []
            r += des.ser_vector(dummy)
            r += struct.pack("<B", flags)
        r += des.ser_vector(self.vin)
        r += des.ser_vector(self.vout)
        if flags & 1:
            if (len(self.wit.vtxinwit) != len(self.vin)):
                # vtxinwit must have the same length as vin
                self.wit.vtxinwit = self.wit.vtxinwit[:len(self.vin)]
                for i in range(len(self.wit.vtxinwit), len(self.vin)):
                    self.wit.vtxinwit.append(TxInWitness())
            r += self.wit.serialize()
        r += des.ser_uint32(self.nLockTime)
        return r

    # Regular serialization is without witness -- must explicitly
    # call serialize_with_witness to include witness data.
    def serialize(self):
        return self.serialize_without_witness()

    # Recalculate the txid (transaction hash without witness)
    def rehash(self):
        self.sha256 = None
        self.calc_sha256()

    # We will only cache the serialization without witness in
    # self.sha256 and self.hash -- those are expected to be the txid.
    def calc_sha256(self, with_witness=False):
        if with_witness:
            # Don't cache the result, just return it
            return uint256_from_str(hash256(self.serialize_with_witness()))

        if self.sha256 is None:
            self.sha256 = uint256_from_str(hash256(self.serialize_without_witness()))
        self.hash = encode(hash256(self.serialize())[::-1], 'hex_codec').decode('ascii')

    def is_valid(self):
        self.calc_sha256()
        for tout in self.vout:
            if tout.nValue < 0 or tout.nValue > 21000000 * COIN:
                return False
        return True

    def __repr__(self):
        return "CTransaction(nVersion=%i vin=%s vout=%s wit=%s nLockTime=%i)" \
            % (self.nVersion, repr(self.vin), repr(self.vout), repr(self.wit), self.nLockTime)

class Address():
    def __init__(self):
        self.version = 0
        self.time = 0
        self.services = 0
        self.ip = b''
        self.port = 0

    def deserialize(self, f):
        self.version = des.deser_uint32(f)
        self.time = des.deser_uint32(f)
        self.services = des.deser_uint64(f)
        self.ip = f.read(16)
        self.port = des.deser_uint16(f, big=True)

        if int.from_bytes(self.ip[0:12], 'big') == 0xffff:
            self.ipv4 = True
        else:
            self.ipv4 = False

    def __repr__(self):
        if self.ipv4:
            ret = ".".join([str(int.from_bytes(self.ip[n:n + 1], 'big')) for n in range(12, 16)])
        else:
            ret = ":".join([self.ip[n:n + 1].hex() for n in range(16)])

        ret += ", port: {}".format(self.port)

        return ret

class AddrInfo():
    def __init__(self):
        self.address = Address()
        self.source = b''
        self.last_success = 0
        self.attempts = 0

    def deserialize(self, f):
        self.address.deserialize(f)
        self.source = f.read(16)
        self.last_success = des.deser_int64(f)
        self.attempts = des.deser_int32(f)

    def __repr__(self):
        return self.address.__repr__()

class Subnet():
    def __init__(self):
        self.network = b''
        self.netmask = b''

    def deserialize(self, f):
        self.network = f.read(16)
        self.netmask = f.read(16)
        self.valid = des.deser_boolean(f)

        if int.from_bytes(self.network[0:12], 'big') == 0xffff:
            self.ipv4 = True
        else:
            self.ipv4 = False

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

class BanEntry():
    def __init__(self):
        self.version = 0
        self.create_time = 0
        self.ban_until = 0
        self.reason = BanReason.UNKNOWN

    def deserialize(self, f):
        self.version = des.deser_int32(f)
        self.create_time = des.deser_int64(f)
        self.ban_until = des.deser_int64(f)
        self.reason = BanReason(des.deser_int8(f))

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
