#!/usr/bin/env python3
#
# Copyright (c) 2010 Gavin Andresen
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""Code for dumping a bitcoind wallet.dat file in a human-readable format."""

import optparse

from wallet import dump_wallet, Wallet
from util import determine_datadir

def main():
    parser = optparse.OptionParser(usage="%prog [options]")
    parser.add_option("--datadir", dest="datadir", default=None,
                      help="Look for files here (defaults to bitcoin default)")
    parser.add_option("--dump", action="store_true", dest="dump_wallet", default=False,
                      help="Print contents of the wallet.dat file (excluding transactions)")
    parser.add_option("--tx", action="store_true", dest="dump_tx", default=False,
                      help="Print transactions in the wallet.dat file")
    (options, args) = parser.parse_args()

    if options.datadir is None:
        datadir = determine_datadir()
    else:
        datadir = options.datadir

    wallet = Wallet(datadir)

    if options.dump_wallet or options.dump_tx:
        dump_wallet(wallet, options.dump_wallet, options.dump_tx)

    wallet.close()

if __name__ == '__main__':
    main()
