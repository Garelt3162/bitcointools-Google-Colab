#!/usr/bin/env python3
#
# Copyright (c) 2017 John Newbery
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""Deserialize peers.dat file."""
import os.path

from datastructures import AddrInfo
import deserialize as des
from util import hash256

class Peers():
    """Represents contents of peers.dat file.

    magic: The network start bytes (4 bytes)
    network (not serialized in file, derived from magic): The network (mainnet, testnet or regtest)
    version: file version number, currently 1 (1 byte)
    marker: length of file key, must equal 0x20 (1 byte)
    key: secret key to randomize bucket select with(32 bytes)
    new: number of new peers (4 bytes)
    tried: number of tried peers (4 bytes)
    no_buckets: number of 'new' buckets, XOR'ed with 2^30 (4 bytes)
    new_table: vector of AddrInfo objects for new peers
    tried_table: vector of AddrInfo objects for tried peers
    bucket_matrix: for each bucket:
      - number of elements
      - for each element: index"""

    def __init__(self):
        self.magic = b''
        self.network = b''
        self.version = 0
        self.key = b''
        self.new = 0
        self.tried = 0
        self.no_buckets = 0
        self.new_table = []
        self.tried_table = []
        self.bucket_matrix = []

    def deserialize(self, f):
        self.magic, self.network = des.deserialize_magic(f)
        self.version = des.deser_uint8(f)
        self.flag = f.read(1)
        assert self.flag == b'\x20'
        self.key = f.read(32)
        self.new = des.deser_int32(f)
        self.tried = des.deser_int32(f)
        self.no_buckets = des.deser_int32(f) ^ 1 << 30

        for _ in range(self.new):
            new_addr = AddrInfo()
            new_addr.deserialize(f)

            self.new_table.append(new_addr)

        for _ in range(self.tried):
            tried_addr = AddrInfo()
            tried_addr.deserialize(f)

            self.tried_table.append(tried_addr)

        for _ in range(self.no_buckets):
            bucket = []
            bucket_size = des.deser_int32(f)
            for __ in range(bucket_size):
                bucket.append(des.deser_int32(f))
            self.bucket_matrix.append(bucket)

        # Verify the checksum
        position = f.tell()
        f.seek(0)
        if hash256(f.read(position)) != f.read(32):
            raise des.SerializationError("File checksum incorrect")

    def __repr__(self):
        ret = "Network magic: 0x{} ({})\n".format(self.magic.hex(), self.network)
        ret += "Version: {}\n".format(self.version)
        ret += "Key: 0x{}\n".format(self.key.hex())
        ret += "new entries: {}\n".format(self.new)
        ret += "tried entries: {}\n".format(self.tried)
        ret += "no_buckets: {}\n".format(self.no_buckets)

        ret += "\nnew peers: [\n"
        for n, new_addr in enumerate(self.new_table):
            ret += "{}. {}\n".format(n, new_addr.__repr__())
        ret += "]\n"

        ret += "\ntried peers: [\n"
        for n, tried_addr in enumerate(self.tried_table):
            ret += "{}. {}\n".format(n, tried_addr.__repr__())
        ret += "]\n"

        ret += "\nBucket matrix:\n\n"
        ret += "\n".join([str(b) for b in self.bucket_matrix])

        return ret

def dump_peers(datadir):
    peers = Peers()
    peers_file = os.path.join(datadir, "peers.dat")

    with open(peers_file, "rb") as f:
        peers.deserialize(f)

    print(peers)
