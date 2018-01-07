# bitcointools

A toolchain for bitcoind data files.

Exit bitcoind before reading any data files.

### bitcoin-wallet-tool.py

DO NOT USE ON MAINNET WALLET FILES CONTAINING MONEY!

This module may be backdoored. The bsddb3 module may be backdoored. The berkeley-db library on your computer may be backdoored. Why risk it?!

Run `bitcoin-wallet-tool.py --help` for usage.

Examples:

Print out wallet keys and transactions:

`bitcoin-wallet-tool.py --dump --tx`

One more thing: DO NOT USE ON MAINNET WALLET FILES CONTAINING MONEY!

### bitcoin-data-tool.py

Parses and prints datadir files. Run `bitcoin-data-tool.py --help` for usage.

Can parse and print the following files:

- `banlist.dat`
- `fee_estimates.dat`
- `mempool.dat`
- `peers.dat`

### testing

Run `python -m unittest` to execute all unit tests. Append `-v` for verbose logging.
