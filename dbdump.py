#!/usr/bin/env python
#
# Code for dumping the bitcoin Berkeley db files in a human-readable format
#
from bsddb.db import *
import logging
import sys

from address import dump_addresses
from wallet import dump_wallet, dump_accounts
from util import determine_db_dir, create_env

def main():
  import optparse
  parser = optparse.OptionParser(usage="%prog [options]")
  parser.add_option("--datadir", dest="datadir", default=None,
                    help="Look for files here (defaults to bitcoin default)")
  parser.add_option("--wallet", action="store_true", dest="dump_wallet", default=False,
                    help="Print out contents of the wallet.dat file")
  parser.add_option("--wallet-tx", action="store_true", dest="dump_wallet_tx", default=False,
                    help="Print transactions in the wallet.dat file")
  parser.add_option("--wallet-tx-filter", action="store", dest="wallet_tx_filter", default="",
                    help="Only print transactions that match given string/regular expression")
  parser.add_option("--accounts", action="store_true", dest="dump_accounts", default="",
                    help="Print out account names, one per line")
  parser.add_option("--address", action="store_true", dest="dump_addr", default=False,
                    help="Print addresses in the addr.dat file")
  (options, args) = parser.parse_args()

  if options.datadir is None:
    db_dir = determine_db_dir()
  else:
    db_dir = options.datadir

  try:
    db_env = create_env(db_dir)
  except DBNoSuchFileError:
    logging.error("Couldn't open " + db_dir)
    sys.exit(1)

  dump_tx = options.dump_wallet_tx
  if len(options.wallet_tx_filter) > 0:
    dump_tx = True
  if options.dump_wallet or dump_tx:
    dump_wallet(db_env, options.dump_wallet, dump_tx, options.wallet_tx_filter)
  if options.dump_accounts:
    dump_accounts(db_env)

  if options.dump_addr:
    dump_addresses(db_env)

  db_env.close()

if __name__ == '__main__':
    main()
