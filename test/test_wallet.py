#!/usr/bin/env python3
#
# Copyright (c) 2018 John Newbery
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""Test wallet.py"""
import unittest

import wallet

class WalletTestCase(unittest.TestCase):
    def test_open(self):
        w = wallet.Wallet("test/files/wallet", "wallet.dat")

        self.assertEqual(w.version, 159900)
        self.assertEqual(w.minimum_version, 159900)
        self.assertEqual(len(w.keys), 39)
        # TODO test other fields
