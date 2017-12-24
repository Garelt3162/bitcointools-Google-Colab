# bitcointools

A toolchain for bitcoind data files.

### bitcoin-wallet-tool.py

Run `bitcoin-wallet-tool.py --help` for usage. Database files are opened read-only, but you should back up your wallet.dat file before using this.

You must quit Bitcoin before reading the wallet database file.

Examples:

Print out wallet keys and transactions:

`bitcoin-wallet-tool.py --wallet --tx`

### bitcoin-data-tool.py

Parses and prints datadir files. Run `bitcoin-data-tool.py --help` for usage.

- `banlist.dat`
- `fee_estimates.dat`
- `mempool.dat`
- `peers.dat`
