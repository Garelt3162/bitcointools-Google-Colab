#!/usr/bin/env python3
#
# Copyright (c) 2010 Gavin Andresen
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""Code for dumping a bitcoind wallet.dat file in a human-readable format."""

import optparse

from wallet import dump_wallet, dump_accounts
from util import determine_datadir

def main():
    parser = optparse.OptionParser(usage="%prog [options]")
    parser.add_option("--accounts", action="store_true", dest="dump_accounts", default="",
                      help="Print account names, one per line")
    parser.add_option("--datadir", dest="datadir", default=None,
                      help="Look for files here (defaults to bitcoin default)")
    parser.add_option("--wallet", action="store_true", dest="dump_wallet", default=False,
                      help="Print contents of the wallet.dat file")
    parser.add_option("--wallet-tx", action="store_true", dest="dump_wallet_tx", default=False,
                      help="Print transactions in the wallet.dat file")
    parser.add_option("--wallet-tx-filter", action="store", dest="wallet_tx_filter", default="",
                      help="Only print transactions that match given string/regular expression")
    (options, args) = parser.parse_args()

    if options.datadir is None:
        datadir = determine_datadir()
    else:
        datadir = options.datadir

    dump_tx = options.dump_wallet_tx
    if len(options.wallet_tx_filter) > 0:
        dump_tx = True
    if options.dump_wallet or dump_tx:
        dump_wallet(datadir, options.dump_wallet, dump_tx, options.wallet_tx_filter)
    if options.dump_accounts:
        dump_accounts(datadir)

if __name__ == '__main__':
    main()
