#!/usr/bin/env python3
#
# Copyright (c) 2017 John Newbery
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""Code for dumping bitcoind datadir files in a human-readable format."""

import optparse
import os

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
        banlist_file = os.path.join(datadir, "banlist.dat")
        dump_banlist(banlist_file)

    if options.fees:
        fee_file = os.path.join(datadir, "fee_estimates.dat")
        dump_fee_estimates(fee_file)

    if options.mempool:
        mempool_file = os.path.join(datadir, "mempool.dat")
        dump_mempool(mempool_file)

    if options.peers:
        peers_file = os.path.join(datadir, "peers.dat")
        dump_peers(peers_file)

if __name__ == '__main__':
    main()
