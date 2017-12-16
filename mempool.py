#!/usr/bin/env python3
#
# Copyright (c) 2017 John Newbery
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""Parse mempool.dat"""
import os.path

from BCDataStream import BCDataStream

class Mempool():
    """Represents contests of mempool.dat file."""
    def __init__(self, mempool_file):
        self.version = 0

        self.parse_mempool_file(mempool_file)

    def parse_mempool_file(self, mempool_file):
        mempool = BCDataStream()
        mempool.clear()

        with open(mempool_file, "rb") as f:
            mempool.write(f.read())

        self.version = mempool.read_uint64()

    def __repr__(self):
        ret = "Version: {}\n".format(self.version)

        return ret

def dump_mempool(datadir):

    mempool = Mempool(os.path.join(datadir, "mempool.dat"))

    print(mempool)
