# bitcointools

A toolchain for bitcoind data files.

Deserializes wallet.dat and peers.dat.

Future work: deserialize banlist.dat, mempool.dat and fee_estimates.dat.

### bitcoin-wallet-tool.py

Run `bitcoin-wallet-tool.py --help` for usage. Database files are opened read-only, but
you should back up your wallet.dat file before using this.

You must quit Bitcoin before reading the wallet database file.

Examples:

Print out wallet keys and transactions:

`bitcoin-wallet-tool.py --wallet --wallet-tx`

Print out all 'received' transactions that aren't yet spent:

`bitcoin-wallet-tool.py --wallet-tx-filter='fromMe:False.*spent:False'`

### bitcoin-data-tool.py

Parses and prints datadir files:

- peers.dat

### fixwallet.py

Half-baked utility that reads a wallet.dat and writes out a new wallet.dat. Do not use this!

### jsonToCSV.py

Read JSON list-of-objects from standard input, writes CSV file to standard output.
Useful for converting bitcoind's listtransactions output to CSV that can be
imported into a spreadsheet.
