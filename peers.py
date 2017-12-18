#!/usr/bin/env python3
#
# Copyright (c) 2017 John Newbery
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""Deserialize peers.dat file."""
import os.path

from datastructures import AddrInfo
import deserialize as des

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
        self.magic, self.network = des.deserialize_magic(f)
        self.version = des.deser_uint8(f)
        self.flag = f.read(1)
        assert self.flag == b'\x20'
        self.key = f.read(32)
        self.new = des.deser_int32(f)
        self.tried = des.deser_int32(f)
        self.buckets = des.deser_int32(f) ^ 1 << 30

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

def dump_peers(datadir):
    peers = Peers()
    peers_file = os.path.join(datadir, "peers.dat")

    with open(peers_file, "rb") as f:
        peers.deserialize(f)

    print(peers)
