#!/usr/bin/env python3
#
# Copyright (c) 2018 John Newbery
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""Test fees.py"""
import unittest

import fees
from serialize import open_bs

class TxConfirmStatsTestCase(unittest.TestCase):
    def test_initialization(self):
        tx_confirm_stats = fees.TxConfirmStats(24)
        self.assertEqual(tx_confirm_stats.no_buckets, 24)

class FeeEstimatesTestCase(unittest.TestCase):
    def test_deserialize(self):
        fee_estimates = fees.FeeEstimates()
        with open_bs("test/files/fee_estimates.dat", "r") as f:
            fee_estimates.deserialize(f)

        self.assertEqual(fee_estimates.version_that_wrote, 159900)
