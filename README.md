### walletdump.py

Run `walletdump.py --help` for usage. Database files are opened read-only, but
you should back up your wallet.dat file before using this.

You must quit Bitcoin before reading the wallet database file.

Examples:

Print out wallet keys and transactions:

`walletdump.py --wallet --wallet-tx`

Print out all 'received' transactions that aren't yet spent:

`walletdump.py --wallet-tx-filter='fromMe:False.*spent:False'`

### fixwallet.py

Half-baked utility that reads a wallet.dat and writes out a new wallet.dat. Do not use this!

### jsonToCSV.py

Read JSON list-of-objects from standard input, writes CSV file to standard output.
Useful for converting bitcoind's listtransactions output to CSV that can be
imported into a spreadsheet.
