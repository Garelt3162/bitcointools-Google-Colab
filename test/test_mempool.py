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
        self.assertEqual(len(mp.txs), 0)  # TODO: test with a mempool.dat containing transactions
