#!/usr/bin/env python3
#
# Copyright (c) 2017 John Newbery
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""Parse peers.dat and banlist.dat."""
from enum import Enum
import os.path
import time

from BCDataStream import BCDataStream
from deserialize import deserialize_magic

class BanReason(Enum):
    UNKNOWN = 0
    NODE_MISBEHAVING = 1
    MANUALLY_ADDED = 2

class Address():
    def __init__(self):
        self.version = 0
        self.time = 0
        self.services = 0
        self.ip = b''
        self.port = 0

    def deserialize(self, f):
        self.version = f.read_uint32()
        self.time = f.read_uint32()
        self.services = f.read_uint64()
        self.ip = f.read_bytes(16)
        self.port = f.read_uint16()

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
        self.source = f.read_bytes(16)
        self.last_success = f.read_int64()
        self.attempts = f.read_int32()

    def __repr__(self):
        return self.address.__repr__()

class Subnet():
    def __init__(self):
        self.network = b''
        self.netmask = b''

    def deserialize(self, f):
        self.network = f.read_bytes(16)
        self.netmask = f.read_bytes(16)
        self.valid = f.read_boolean()

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
        self.version = f.read_int32()
        self.create_time = f.read_int64()
        self.ban_until = f.read_int64()
        self.reason = BanReason(int.from_bytes(f.read_bytes(1), 'big'))

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

class Peers():
    """Represents contents of peers.dat file."""
    def __init__(self):
        self.magic = b''
        self.network = b''
        self.version = 0
        self.key = b''
        self.new = 0
        self.tried = 0
        self.buckets = 0
        self.new_table = []
        self.tried_table = []

    def deserialize(self, f):
        self.magic, self.network = deserialize_magic(f)
        self.version = int.from_bytes(f.read_bytes(1), 'big')
        self.flag = f.read_bytes(1)
        assert self.flag == b'\x20'
        self.key = f.read_bytes(32)
        self.new = f.read_int32()
        self.tried = f.read_int32()
        self.buckets = f.read_int32() ^ 1 << 30

        for _ in range(self.new):
            new_addr = AddrInfo()
            new_addr.deserialize(f)

            self.new_table.append(new_addr)

        for _ in range(self.tried):
            tried_addr = AddrInfo()
            tried_addr.deserialize(f)

            self.tried_table.append(tried_addr)

    def __repr__(self):
        ret = "Network magic: 0x{} ({})\n".format(self.magic.hex(), self.network)
        ret += "Version: {}\n".format(self.version)
        ret += "Key: 0x{}\n".format(self.key.hex())
        ret += "new entries: {}\n".format(self.new)
        ret += "tried entries: {}\n".format(self.tried)
        ret += "buckets: {}\n".format(self.buckets)
        if self.new_table:
            ret += "new peers: [\n"
            for new_addr in self.new_table:
                ret += "    {}\n".format(new_addr.__repr__())
        ret += "]\n"
        if self.tried_table:
            ret += "tried peers: [\n"
            for tried_addr in self.tried_table:
                ret += "    {}\n".format(tried_addr.__repr__())
        ret += "]\n"

        return ret

class Banlist():
    """Represents contents of banlist.dat file."""
    def __init__(self):
        self.magic = b''
        self.network = b''
        self.banmap = {}

    def deserialize(self, f):
        self.magic, self.network = deserialize_magic(f)
        bl_len = f.read_compact_size()

        for _ in range(bl_len):
            ban = Ban()
            ban.deserialize(f)

            self.banmap[ban.subnet] = ban.ban_entry

    def __repr__(self):
        ret = "Network magic: 0x{} ({})\n".format(self.magic.hex(), self.network)
        if self.banmap:
            ret += "ban entries:\n"
        for subnet, ban in self.banmap.items():
            ret += "   [{}]: {}".format(subnet.__repr__(), ban.__repr__())

        return ret

def dump_peers(datadir):
    peers_file = os.path.join(datadir, "peers.dat")

    peers_ds = BCDataStream()
    peers_ds.clear()

    with open(peers_file, "rb") as f:
        peers_ds.write(f.read())

    peers = Peers()
    peers.deserialize(peers_ds)

    print(peers)

def dump_banlist(datadir):
    banlist_file = os.path.join(datadir, "banlist.dat")

    banlist_ds = BCDataStream()
    banlist_ds.clear()

    with open(banlist_file, "rb") as f:
        banlist_ds.write(f.read())

    banlist = Banlist()
    banlist.deserialize(banlist_ds)

    print(banlist)
