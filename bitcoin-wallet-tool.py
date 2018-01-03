#!/usr/bin/env python3
#
# Copyright (c) 2010 Gavin Andresen
# Copyright (c) 2018 John Newbery
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""Code for dumping a bitcoind wallet.dat file in a human-readable format."""

import optparse

from wallet import dump_wallet, Wallet
from util import determine_datadir

def main():
    parser = optparse.OptionParser(usage="%prog [options]")
    parser.add_option("--dir", dest="dir", default=None,
                      help="Wallet directory (defaults to bitcoin default datadir)")
    parser.add_option("--name", dest="name", default="wallet.dat",
                      help="Name of wallet file (defaults to wallet.dat)")
    parser.add_option("--dump", action="store_true", dest="dump_wallet", default=False,
                      help="Print contents of the wallet.dat file (excluding transactions)")
    parser.add_option("--tx", action="store_true", dest="dump_tx", default=False,
                      help="Print transactions in the wallet.dat file")
    (options, args) = parser.parse_args()

    if options.dir is None:
        wallet_dir = determine_datadir()
    else:
        wallet_dir = options.dir

    wallet = Wallet(wallet_dir, options.name)

    if options.dump_wallet or options.dump_tx:
        dump_wallet(wallet, options.dump_wallet, options.dump_tx)

    wallet.close()

if __name__ == '__main__':
    main()
