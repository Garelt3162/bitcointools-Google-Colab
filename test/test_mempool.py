#!/usr/bin/env python3
#
# Copyright (c) 2018 John Newbery
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""Test mempool.py"""
import unittest

import mempool
from serialize import open_bs

class MempoolTestCase(unittest.TestCase):
    def test_deserialize(self):
        mp = mempool.Mempool()
        with open_bs("test/files/mempool.dat", "r") as f:
            mp.deserialize(f)

        self.assertEqual(mp.version, 1)

        # Verify the correct number of txs and data on the first tx
        self.assertEqual(len(mp.txs), 12)
        self.assertEqual(mp.txs[0].tx.txid, '2e7d9174ff36ede49bce664a002bf9d0bd6d01da04f266de1fd1f3457f245bb0')
        self.assertEqual(mp.txs[0].time, 1515261281)
        self.assertEqual(mp.txs[0].fee_delta, 1000)

        # Verify the correct number of fee_deltas and data on the fee_delta.
        # Note that map_deltas only contains deltas for transactions which aren't included
        # in the tx list (ie that aren't currently in the mempool).
        self.assertEqual(len(mp.map_deltas), 1)
        self.assertEqual(mp.map_deltas['93ca570ba85fef02846a8dea878b9e82ea1e114a6b2b4206b8f64f3abc76ebfc'], -1001)
