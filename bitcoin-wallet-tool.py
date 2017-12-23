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
    parser.add_option("--accounts", action="store_true", dest="dump_accounts", default="",
                      help="Print account names, one per line")
    parser.add_option("--datadir", dest="datadir", default=None,
                      help="Look for files here (defaults to bitcoin default)")
    parser.add_option("--dump-wallet", action="store_true", dest="dump_wallet", default=False,
                      help="Print contents of the wallet.dat file")
    parser.add_option("--wallet-tx", action="store_true", dest="dump_wallet_tx", default=False,
                      help="Print transactions in the wallet.dat file")
    parser.add_option("--wallet-tx-filter", action="store", dest="wallet_tx_filter", default="",
                      help="Only print transactions that match given string/regular expression")
    parser.add_option("--out", dest="outfile", default="walletNEW.dat",
                      help="Name of output file (default: walletNEW.dat)")
    parser.add_option("--clean", action="store_true", dest="clean", default=False,
                      help="Clean out old, spent change addresses and transactions")
    parser.add_option("--skipkey", dest="skipkey",
                      help="Skip entries with keys that contain given string")
    parser.add_option("--tweakspent", dest="tweakspent",
                      help="Tweak transaction to mark unspent")
    (options, args) = parser.parse_args()

    if options.datadir is None:
        datadir = determine_datadir()
    else:
        datadir = options.datadir

    wallet = Wallet(datadir)

    dump_tx = options.dump_wallet_tx
    if len(options.wallet_tx_filter) > 0:
        dump_tx = True
    if options.dump_wallet or dump_tx:
        dump_wallet(wallet, options.dump_wallet, dump_tx, options.wallet_tx_filter)
    # if options.dump_accounts:
    #     dump_accounts(wallet)
    # if options.clean:
    #     trim_wallet(wallet, options.outfile)
    # if options.skipkey:

    #     def pre_put_callback(type, data):
    #         if options.skipkey in data['__key__']:
    #             return False
    #         return True

    #     rewrite_wallet(db_env, options.outfile, pre_put_callback)
    # if options.tweakspent:
    #     txid = options.tweakspent.decode('hex_codec')[::-1]

    #     def tweak_spent_callback(type, data):
    #         if txid in data['__key__']:
    #             data['__value__'] = data['__value__'][:-1] + '\0'
    #         return True

    #     rewrite_wallet(db_env, options.outfile, tweak_spent_callback)
    #     pass

    wallet.close()

if __name__ == '__main__':
    main()
