#!/usr/bin/env python3
#
# Copyright (c) 2018 John Newbery
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""Test peers.py"""
import unittest

import peers
from serialize import open_bs

class PeersTestCase(unittest.TestCase):
    def test_deserialize(self):
        ps = peers.Peers()
        with open_bs("test/files/peers.dat", "r") as f:
            ps.deserialize(f)

        self.assertEqual(ps.magic, b'\xf9\xbe\xb4\xd9')
        self.assertEqual(ps.network, 'mainnet')
        self.assertEqual(ps.version, 1)
        # TODO test other fields
