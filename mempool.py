#!/usr/bin/env python3
#
# Copyright (c) 2017 John Newbery
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""Parse mempool.dat"""
import time

from datastructures import Transaction
from serialize import open_bs

class MempoolTx():
    """A transaction with additional mempool metadata.

    TODO: move this class in datastructures.py.

    tx: the Transaction object
    time: TODO
    fee_delta: TODO."""
    def __init__(self, tx, time, fee_delta):
        self.tx = tx
        self.time = time
        self.fee_delta = fee_delta

    def __repr__(self):
        return "txid: {}, entered_mempool: {}, fee_delta: {}".format(self.tx.txid, time.ctime(self.time), self.fee_delta)

class Mempool():
    """Represents contents of mempool.dat file.

    version: TODO
    txs: a list of MempoolTx objects."""
    def __init__(self):
        self.version = 0
        self.txs = []

    def deserialize(self, f):
        self.version = f.deser_int64()

        txs = f.deser_int64()

        for _ in range(txs):
            tx = Transaction()
            tx.deserialize(f)
            time = f.deser_int64()
            fee_delta = f.deser_int64()

            self.txs.append(MempoolTx(tx, time, fee_delta))

    def __repr__(self):
        ret = "Version: {}\n".format(self.version)
        if self.txs:
            ret += "mempool txs:\n"
            ret += "\n".join(["  {}".format(tx) for tx in self.txs])
        else:
            ret += "mempool empty"

        return ret

def dump_mempool(mempool_file):
    mempool = Mempool()

    with open_bs(mempool_file, "r") as f:
        mempool.deserialize(f)

    print(mempool)
