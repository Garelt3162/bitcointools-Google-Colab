#!/usr/bin/env python3
#
# Copyright (c) 2017 John Newbery
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""Parse peers.dat and banlist.dat."""
import os.path

from BCDataStream import BCDataStream
from deserialize import parse_magic

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
        banlist = BCDataStream()
        banlist.clear()

        with open(banlist_file, "rb") as f:
            banlist.write(f.read())

        self.magic, self.network = parse_magic(banlist)

    def __repr__(self):
        return "Network magic: 0x{} ({})".format(self.magic.hex(), self.network)

def dump_banlist(datadir):

    banlist = Banlist(os.path.join(datadir, "banlist.dat"))

    print(banlist)
