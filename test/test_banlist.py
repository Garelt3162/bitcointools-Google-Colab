#!/usr/bin/env python3
#
# Copyright (c) 2018 John Newbery
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""Test banlist.py"""
import unittest

import banlist
from serialize import open_bs

class BanlistTestCase(unittest.TestCase):
    def test_deserialize(self):
        bl = banlist.Banlist()
        with open_bs("test/files/banlist.dat", "r") as f:
            bl.deserialize(f)

        self.assertEqual(bl.magic, b'\xf9\xbe\xb4\xd9')
        self.assertEqual(bl.network, 'mainnet')
        self.assertEqual(len(bl.banmap), 1)
