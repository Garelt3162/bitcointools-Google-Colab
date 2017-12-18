#!/usr/bin/env python3
#
# Copyright (c) 2017 John Newbery
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""Code for dumping bitcoind datadir files in a human-readable format."""

import optparse

from banlist import dump_banlist
from fees import dump_fee_estimates
from mempool import dump_mempool
from peers import dump_peers
from util import determine_datadir

def main():
    parser = optparse.OptionParser(usage="%prog [options]")
    parser.add_option("--datadir", dest="datadir", default=None,
                      help="Look for files here (defaults to bitcoin default)")
    parser.add_option("--banlist", action="store_true", default=False,
                      help="Print out contents of the banlist.dat file")
    parser.add_option("--fees", action="store_true", default=False,
                      help="Print out contents of the fee_estimates.dat file")
    parser.add_option("--mempool", action="store_true", default=False,
                      help="Print out contents of the mempool.dat file")
    parser.add_option("--peers", action="store_true", default=False,
                      help="Print out contents of the peers.dat file")
    (options, args) = parser.parse_args()

    if options.datadir is None:
        datadir = determine_datadir()
    else:
        datadir = options.datadir

    if options.banlist:
        dump_banlist(datadir)

    if options.fees:
        dump_fee_estimates(datadir)

    if options.mempool:
        dump_mempool(datadir)

    if options.peers:
        dump_peers(datadir)

if __name__ == '__main__':
    main()
