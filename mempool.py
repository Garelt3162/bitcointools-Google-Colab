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

    This is not a true bitcoind data structure. It is directly serialized as Transaction|time|fee_delta.

    tx: the Transaction object
    time: the time the transaction entered the mempool.
    fee_delta: the fee delta set by the `prioritisetransaction` RPC."""
    def __init__(self, tx, time, fee_delta):
        self.tx = tx
        self.time = time
        self.fee_delta = fee_delta

    def __repr__(self):
        return "txid: {}, entered_mempool: {}, fee_delta: {}".format(self.tx.txid, time.ctime(self.time), self.fee_delta)

class Mempool():
    """Represents contents of mempool.dat file.

    version: the mempool file version. Must equal 1.
    txs: a list of MempoolTx objects.
    map_deltas: a map of fee deltas from txid to fee_delta for txs that aren't in the mempool."""
    def __init__(self):
        self.version = 0
        self.txs = []
        self.map_deltas = {}

    def deserialize(self, f):
        self.version = f.deser_int64()
        if self.version != 1:
            raise SerializationError("Corrupt mempool.dat file. Version {} != 1".format(self.version))

        txs = f.deser_int64()

        for _ in range(txs):
            tx = Transaction()
            tx.deserialize(f)
            time = f.deser_int64()
            fee_delta = f.deser_int64()

            self.txs.append(MempoolTx(tx, time, fee_delta))

        map_deltas_len = f.deser_compact_size()
        for _ in range(map_deltas_len):
            txid = f.deser_uint256()
            delta = f.deser_int64()
            self.map_deltas[hex(txid)[2:]] = delta

    def __repr__(self):
        ret = "Version: {}\n".format(self.version)
        if self.txs:
            ret += "\nmempool txs:\n"
            ret += "\n".join(["  {}".format(tx) for tx in self.txs])
        else:
            ret += "\nmempool empty"

        if self.map_deltas:
            ret += "\nmap_deltas:\n"
            ret += "\n".join(["  {}: {}".format(txid.hex(), delta) for txid, delta in self.map_deltas.items()])
        else:
            ret += "\nno fee_deltas"

        return ret

def dump_mempool(mempool_file):
    mempool = Mempool()

    with open_bs(mempool_file, "r") as f:
        mempool.deserialize(f)

    print(mempool)
