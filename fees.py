#!/usr/bin/env python3
#
# Copyright (c) 2017 John Newbery
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""Parse fee_estimates.dat"""
from serialize import open_bs, SerializationError

class TxConfirmStats():
    """Tracks buckets of transactions and how long it took for them to confirm in a block.

    TODO: The following fields are actually from the TxConfirmStats class and should be deserialized separately,
    since a v15.0 fee_estimates.dat files contains 3 TxConfirmStats objects (feeStats, shortStats and longStats).
    decay: TODO
    scale: TODO
    max_periods:TODO
    max_confirms:TODO
    avg :TODO
    txCtAvg :TODO
    confAvg :TODO
    failAvg :TODO"""

    def __init__(self, no_buckets):
        self.no_buckets = no_buckets
        self.decay = 0
        self.scale = 0
        self.max_periods = 0
        self.max_confirms = 0
        self.avg = []
        self.txCtAvg = []
        self.confAvg = []
        self.failAvg = []

    def __repr__(self):
        ret = "Decay: {}\n".format(self.decay)
        ret += "Scale: {}\n".format(self.scale)
        ret += "Avg Fees: {}\n".format(self.avg)
        ret += "Bucket tx counts: {}\n".format(self.txCtAvg)
        ret += "confAvg: {}\n".format(self.confAvg)
        ret += "failAvg: {}\n".format(self.confAvg)
        ret += "max periods: {}\n".format(self.max_periods)
        ret += "max confirms: {}\n".format(self.max_confirms)

        return ret

    def deserialize(self, f):
        self.decay = f.deser_double()
        self.scale = f.deser_uint32()

        avg_size = f.deser_compact_size()
        if avg_size != self.no_buckets:
            raise SerializationError("Corrupt estimates file. Mismatch in feerate average bucket count")
        for _ in range(self.no_buckets):
            self.avg.append(f.deser_double())

        tx_ct_avg_size = f.deser_compact_size()
        if tx_ct_avg_size != self.no_buckets:
            raise SerializationError("Corrupt estimates file. Mismatch in tx count bucket count")
        for _ in range(self.no_buckets):
            self.txCtAvg.append(f.deser_double())

        no_block_targets = f.deser_compact_size()
        for _ in range(no_block_targets):
            conf_avg = []
            no_conf_avg = f.deser_compact_size()
            if no_conf_avg != self.no_buckets:
                raise SerializationError("Corrupt estimates file. Mismatch in feerate conf average bucket count")

            for __ in range(self.no_buckets):
                conf_avg.append(f.deser_double())

            self.confAvg.append(conf_avg)

        self.max_periods = len(self.confAvg)
        self.max_confirms = self.scale * self.max_periods

        no_block_targets = f.deser_compact_size()
        for _ in range(no_block_targets):
            fail_avg = []
            no_fail_avg = f.deser_compact_size()
            if no_fail_avg != self.no_buckets:
                raise SerializationError("Corrupt estimates file. Mismatch in one of failure average bucket counts")

            for __ in range(self.no_buckets):
                fail_avg.append(f.deser_double())

            self.failAvg.append(fail_avg)

class FeeEstimates():
    """Represents contests of fee_estimates.dat file.

    version_required: the version of bitcoind that wrote this fee estimates file.
    version_that_wrote: the minimum version of bitcoind that can read this fee estimates file.
    file_best_seen_height: the height of the higest block that was processed for this fee estimates file.
    file_historical_first and file_historical_best: the spam of bloacks for which bitcoind was tracking
        fee estimates when the fee estimate file was written. Used by bitcoind to know what targets it can
        successfully evaluate with the data in the file.
    fee_stats: a medium range TxConfirmStats object tracking transactions confirmed in up to 48 blocks (granularity: 2 blocks)
    short_stats: a short range TxConfirmStats object tracking transactions confirmed in up to 12 blocks (granularity: 1 block)
    long_stats: a long range TxConfirmStats object tracking transactions confirmed in up to 1008 blocks (granularity: 24 blocks)
    buckets: TODO."""

    def __init__(self):
        self.version_required = 0
        self.version_that_wrote = 0
        self.file_best_seen_height = 0
        self.file_historical_first = 0
        self.file_historical_best = 0
        self.buckets = []
        self.fee_stats = None
        self.short_stats = None
        self.long_stats = None

    def __repr__(self):
        ret = "Version required: {}\n".format(self.version_required)
        ret += "Version that wrote: {}\n".format(self.version_that_wrote)
        ret += "File best seen height: {}\n".format(self.file_best_seen_height)
        ret += "File historical first: {}\n".format(self.file_historical_first)
        ret += "File historical best: {}\n".format(self.file_historical_best)
        ret += "Buckets: {}\n".format(self.buckets)
        ret += "Short Term Fee Stats:\n"
        ret += self.short_stats.__repr__()
        ret += "Medium Term Fee Stats:\n"
        ret += self.fee_stats.__repr__()
        ret += "Long Term Fee Stats:\n"
        ret += self.long_stats.__repr__()

        return ret

    def deserialize(self, f):
        self.version_required = f.deser_uint32()
        self.version_that_wrote = f.deser_uint32()
        if self.version_that_wrote < 149900:
            raise SerializationError("Cannot read fee_estimates.dat file with version < 149900")

        self.file_best_seen_height = f.deser_uint32()
        self.file_historical_first = f.deser_uint32()
        self.file_historical_best = f.deser_uint32()

        if self.file_historical_first > self.file_historical_best or self.file_historical_first > self.file_best_seen_height:
            raise SerializationError("Corrupt estimates file. Historical block range for estimates is invalid")

        no_buckets = f.deser_compact_size()
        if no_buckets <= 1 or no_buckets > 1000:
            raise SerializationError("Corrupt estimates file. Must have between 2 and 1000 feerate buckets")

        for _ in range(no_buckets):
            self.buckets.append(f.deser_double())

        # Deserialize the TxConfirmStats parts
        self.fee_stats = TxConfirmStats(no_buckets)
        self.fee_stats.deserialize(f)
        self.short_stats = TxConfirmStats(no_buckets)
        self.short_stats.deserialize(f)
        self.long_stats = TxConfirmStats(no_buckets)
        self.long_stats.deserialize(f)

def dump_fee_estimates(fee_file):

    fee_estimates = FeeEstimates()

    with open_bs(fee_file, "r") as f:
        fee_estimates.deserialize(f)

    print(fee_estimates)
