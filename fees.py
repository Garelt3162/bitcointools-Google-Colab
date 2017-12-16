#!/usr/bin/env python3
#
# Copyright (c) 2017 John Newbery
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""Parse fee_estimates.dat"""
import os.path

from BCDataStream import BCDataStream

class FeeEstimates():
    """Represents contests of fee_estimates.dat file."""
    def __init__(self, fee_file):
        self.version_required = 0
        self.version_that_wrote = 0

        self.parse_fee_file(fee_file)

    def parse_fee_file(self, fee_file):
        fee_estimates = BCDataStream()
        fee_estimates.clear()

        with open(fee_file, "rb") as f:
            fee_estimates.write(f.read())

        self.version_required = fee_estimates.read_uint32()
        self.version_that_wrote = fee_estimates.read_uint32()

    def __repr__(self):
        ret = "Version required: {}\n".format(self.version_required)
        ret += "Version that wrote: {}\n".format(self.version_that_wrote)

        return ret

def dump_fee_estimates(datadir):

    fee_estimates = FeeEstimates(os.path.join(datadir, "fee_estimates.dat"))

    print(fee_estimates)
