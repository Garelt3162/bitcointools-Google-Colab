#!/usr/bin/env python3
#
# Copyright (c) 2017 John Newbery
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""Parse fee_estimates.dat"""
from serialize import open_bs, SerializationError

class FeeEstimates():
    """Represents contests of fee_estimates.dat file.

    version_required: TODO
    version_that_wrote: TODO
    file_best_seen_height: TODO
    file_historical_first: TODO
    file_historical_best: TODO


    TODO: The following fields are actually from the TxConfirmStats class and should be deserialized separately,
    since a v15.0 fee_estimates.dat files contains 3 TxConfirmStats objects (feeStats, shortStats and longStats).
    buckets: TODO
    decay: TODO
    scale: TODO
    max_periods:TODO
    max_confirms:TODO
    avg :TODO
    txCtAvg :TODO
    confAvg :TODO
    failAvg :TODO"""
    def __init__(self):
        self.version_required = 0
        self.version_that_wrote = 0
        self.file_best_seen_height = 0
        self.file_historical_first = 0
        self.file_historical_best = 0
        self.buckets = []
        self.decay = 0
        self.scale = 0
        self.max_periods = 0
        self.max_confirms = 0
        self.avg = []
        self.txCtAvg = []
        self.confAvg = []
        self.failAvg = []

    def __repr__(self):
        ret = "Version required: {}\n".format(self.version_required)
        ret += "Version that wrote: {}\n".format(self.version_that_wrote)
        ret += "File best seen height: {}\n".format(self.file_best_seen_height)
        ret += "File historical first: {}\n".format(self.file_historical_first)
        ret += "File historical best: {}\n".format(self.file_historical_best)
        ret += "Buckets: {}\n".format(self.buckets)
        ret += "Decay: {}\n".format(self.decay)
        ret += "Scale: {}\n".format(self.scale)
        ret += "Avg Fees: {}\n".format(self.avg)
        ret += "Bucket tx counts: {}\n".format(self.txCtAvg)
        ret += "confAvg: {}\n".format(self.confAvg)
        ret += "failAvg: {}\n".format(self.confAvg)
        ret += "max periods: {}\n".format(self.max_periods)
        ret += "max confirms: {}\n".format(self.max_confirms)

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

        self.decay = f.deser_double()
        self.scale = f.deser_uint32()

        avg_size = f.deser_compact_size()
        if avg_size != no_buckets:
            raise SerializationError("Corrupt estimates file. Mismatch in feerate average bucket count")
        for _ in range(no_buckets):
            self.avg.append(f.deser_double())

        txCtAvg_size = f.deser_compact_size()
        if txCtAvg_size != no_buckets:
            raise SerializationError("Corrupt estimates file. Mismatch in tx count bucket count")
        for _ in range(no_buckets):
            self.txCtAvg.append(f.deser_double())

        no_block_targets = f.deser_compact_size()
        for _ in range(no_block_targets):
            conf_avg = []
            no_conf_avg = f.deser_compact_size()
            if no_conf_avg != no_buckets:
                raise SerializationError("Corrupt estimates file. Mismatch in feerate conf average bucket count")

            for __ in range(no_buckets):
                conf_avg.append(f.deser_double())

            self.confAvg.append(conf_avg)

        self.max_periods = len(self.confAvg)
        self.max_confirms = self.scale * self.max_periods

        no_block_targets = f.deser_compact_size()
        for _ in range(no_block_targets):
            fail_avg = []
            no_fail_avg = f.deser_compact_size()
            if no_fail_avg != no_buckets:
                raise SerializationError("Corrupt estimates file. Mismatch in one of failure average bucket counts")

            for __ in range(no_buckets):
                fail_avg.append(f.deser_double())

            self.failAvg.append(fail_avg)

def dump_fee_estimates(fee_file):

    fee_estimates = FeeEstimates()

    with open_bs(fee_file, "r") as f:
        fee_estimates.deserialize(f)

    print(fee_estimates)
