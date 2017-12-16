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
from deserialize import parse_magic

class BanReason(Enum):
    UNKNOWN = 0
    NODE_MISBEHAVING = 1
    MANUALLY_ADDED = 2

class Peers():
    """Represents contests of peers.dat file."""
    def __init__(self, peers_file):
        self.magic = b''
        self.network = b''
        self.version = 0

        self.parse_peers_file(peers_file)

    def parse_peers_file(self, peers_file):
        peers = BCDataStream()
        peers.clear()

        with open(peers_file, "rb") as f:
            peers.write(f.read())

        self.magic, self.network = parse_magic(peers)
        self.version = int.from_bytes(peers.read_bytes(1), 'big')
        self.flag = peers.read_bytes(1)
        assert self.flag == b'\x20'
        self.key = peers.read_bytes(32)
        self.new = peers.read_int32()
        self.tried = peers.read_int32()
        self.buckets = peers.read_int32() ^ 1 << 30

    def __repr__(self):
        ret = "Network magic: 0x{} ({})\n".format(self.magic.hex(), self.network)
        ret += "Version: {}\n".format(self.version)
        ret += "Key: 0x{}\n".format(self.key.hex())
        ret += "new entries: {}\n".format(self.new)
        ret += "tried entries: {}\n".format(self.tried)
        ret += "buckets: {}\n".format(self.buckets)

        return ret

def dump_peers(datadir):

    peers = Peers(os.path.join(datadir, "peers.dat"))

    print(peers)

class Banlist():
    """Represents contests of banlist.dat file."""
    def __init__(self, banlist_file):
        self.magic = b''
        self.network = b''
        self.banmap = {}

        self.parse_banlist_file(banlist_file)

    def parse_banlist_file(self, banlist_file):
        banlist = BCDataStream()
        banlist.clear()

        with open(banlist_file, "rb") as f:
            banlist.write(f.read())

        self.magic, self.network = parse_magic(banlist)

        bl_len = banlist.read_compact_size()

        for _ in range(bl_len):
            ban = Ban.parse(banlist)

            self.banmap[ban.subnet] = ban.ban_entry

    def __repr__(self):
        ret = "Network magic: 0x{} ({})\n".format(self.magic.hex(), self.network)
        if self.banmap:
            ret += "ban entries:\n"
        for subnet, ban in self.banmap.items():
            ret += "   [{}]: {}".format(subnet.__repr__(), ban.__repr__())

        return ret

class Subnet():
    def __init__(self, network, netmask):
        self.network = network
        self.netmask = netmask

        if int.from_bytes(self.network[0:12], 'big'):
            self.ipv4 = True
        else:
            self.ipv4 = False

    def __repr__(self):
        if self.ipv4:
            ret = ".".join([str(int.from_bytes(self.network[n:n + 1], 'big')) for n in range(12, 16)])
            ret += ", netmask: "
            ret += ".".join([str(int.from_bytes(self.netmask[n:n + 1], 'big')) for n in range(12, 16)])

        return ret

class BanEntry():
    def __init__(self, version, create_time, ban_until, reason):
        self.version = version
        self.create_time = create_time
        self.ban_until = ban_until
        self.reason = reason

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
    def __init__(self, network, netmask, valid, version, create_time, ban_until, reason):
        self.subnet = Subnet(network, netmask)
        self.valid = valid
        self.ban_entry = BanEntry(version, create_time, ban_until, reason)

    @classmethod
    def parse(cls, s):
        """Parse a ban entry from the start of a bytestream. Return a Ban object."""
        network = s.read_bytes(16)
        netmask = s.read_bytes(16)
        valid = s.read_boolean()
        version = s.read_int32()
        create_time = s.read_int64()
        ban_until = s.read_int64()
        reason = BanReason(int.from_bytes(s.read_bytes(1), 'big'))

        return cls(network, netmask, valid, version, create_time, ban_until, reason)

def dump_banlist(datadir):

    banlist = Banlist(os.path.join(datadir, "banlist.dat"))

    print(banlist)
