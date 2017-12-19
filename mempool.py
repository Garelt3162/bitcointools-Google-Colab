#!/usr/bin/env python3
#
# Copyright (c) 2017 John Newbery
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""Parse mempool.dat"""
import os.path
import struct
import time

from datastructures import Transaction

class MempoolTx():
    def __init__(self, tx, time, fee_delta):
        self.tx = tx
        self.time = time
        self.fee_delta = fee_delta

    def __repr__(self):
        ret = "Transaction: {}\n".format(self.tx)
        ret += "entered mempool: {}, fee delta: {}".format(time.ctime(self.time), self.fee_delta)

        return ret

class Mempool():
    """Represents contents of mempool.dat file."""
    def __init__(self):
        self.version = 0
        self.txs = []

    def deserialize(self, f):
        self.version = struct.unpack("<q", f.read(8))[0]

        txs = struct.unpack("<q", f.read(8))[0]

        for _ in range(txs):
            tx = Transaction()
            tx.deserialize(f)
            time = struct.unpack("<q", f.read(8))[0]
            fee_delta = struct.unpack("<q", f.read(8))[0]

            self.txs.append(MempoolTx(tx, time, fee_delta))

    def __repr__(self):
        ret = "Version: {}\n".format(self.version)
        ret += "mempool txs: [\n"
        for tx in self.txs:
            ret += "    {}\n".format(tx.__repr__())
        ret += "]"

        return ret

def dump_mempool(datadir):

    mempool_file = os.path.join(datadir, "mempool.dat")

    with open(mempool_file, "rb") as f:
        mempool = Mempool()
        mempool.deserialize(f)

    print(mempool)
