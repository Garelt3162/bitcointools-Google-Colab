#!/usr/bin/env python3
#
# Copyright (c) 2010 Gavin Andresen
# Copyright (c) 2018 John Newbery
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""Code for parsing the wallet.dat file"""

from base58 import public_key_to_bc_address
import logging
import sys

from bsddb3.db import (  # pip3 install bsddb3
    DB,
    DBEnv,
    DBError,
    DBNoSuchFileError,
    DB_BTREE,
    DB_CREATE,
    DB_INIT_LOCK,
    DB_INIT_LOG,
    DB_INIT_MPOOL,
    DB_INIT_TXN,
    DB_RDONLY,
    DB_RECOVER,
    DB_THREAD,
)

from datastructures import WalletTransaction, BlockLocator, KeyPool, Account, HDChain, AccountingEntry, KeyMeta
from serialize import BCBytesStream
from util import short_hex, determine_datadir

VERSION_HD_CHAIN_SPLIT = 2
VERSION_WITH_HDDATA = 10

def create_env(db_dir=None):
    if db_dir is None:
        db_dir = determine_datadir()
    db_env = DBEnv(0)
    db_env.open(db_dir, DB_CREATE | DB_INIT_LOCK | DB_INIT_LOG | DB_INIT_MPOOL | DB_INIT_TXN | DB_THREAD | DB_RECOVER)
    return db_env

class Wallet():
    """Represents contents of wallet.dat file.

    accounting_entries: TODO
    accounts: TODO
    default_key: TODO
    hd_chain: TODO
    key_meta: TODO
    keys: TODO
    minimum_version: TODO
    names: TODO
    orderposnext: TODO
    owner_keys: TODO
    pool: TODO
    purposes: TODO
    records: TODO
    version: TODO
    wallet_transactions: TODO
    wkeys: TODO

    self.name: TODO"""

    def __init__(self, wallet_dir, name):
        self.accounting_entries = []
        self.accounts = {}
        self.default_key = b''
        self.hd_chain = None
        self.key_meta = []
        self.keys = {}
        self.minimum_version = 0
        self.names = {}
        self.orderposnext = 0
        self.owner_keys = {}
        self.pool = {}
        self.purposes = {}
        self.records = []
        self.version = 0
        self.wallet_transactions = []
        self.wkeys = {}

        self.name = name
        try:
            self.db_env = create_env(wallet_dir)
        except DBNoSuchFileError:
            logging.error("Couldn't open " + wallet_dir)
            sys.exit(1)

        self.open_wallet()
        self.parse_wallet()

    def __repr__(self):
        ret = "version: {}\n".format(self.version)
        ret += "minimum_version: {}\n".format(self.minimum_version)
        ret += "orderposnext: {}\n".format(self.orderposnext)
        if self.best_block:
            ret += "best_block: {}".format(self.best_block.__repr__())
        if self.best_block_no_merkle:
            ret += "best_block_no_merkle: {}".format(self.best_block_no_merkle.__repr__())
        if self.default_key != b'':
            ret += "default_key: {}\n".format(self.default_key)
        if self.hd_chain:
            ret += "hd_chain:\n  {}\n".format(self.hd_chain)
        if self.keys:
            ret += "keys:\n"
            ret += "\n".join(["  pub_key: {}, address: {}, priv_key: {}".format(pub_key.hex(), public_key_to_bc_address(pub_key), short_hex(priv_key)) for pub_key, priv_key in self.keys.items()])
            ret += "\n"
        if self.wkeys:
            ret += "wkeys:\n"
            ret += "\n".join(["  {}".format(wkey) for wkey in self.wkeys])
            ret += "\n"
        if self.names:
            ret += "names:\n"
            ret += "\n".join(["  address: {}, name: {}".format(address, name) for name, address in self.names.items()])
            ret += "\n"
        if self.purposes:
            ret += "purposes:\n"
            ret += "\n".join(["  address: {}, purpose: {}".format(purpose, address) for purpose, address in self.purposes.items()])
            ret += "\n"
        if self.pool:
            ret += "key_pool:\n"
            ret += "\n".join(["  {}. {}".format(n, key_pool) for n, key_pool in self.pool.items()])
            ret += "\n"
        if self.accounts:
            ret += "accounts:\n"
            ret += "\n".join(["  {}: {}".format(account_name, account) for account_name, account in self.accounts.items()])
            ret += "\n"
        if self.accounting_entries:
            ret += "accounting entries:\n"
            ret += "\n".join(["  {}".format(account_entry) for account_entry in self.accounting_entries])
            ret += "\n"
        if self.key_meta:
            ret += "key metadata:\n"
            ret += "\n".join(["  {}".format(key_meta) for key_meta in self.key_meta])
            ret += "\n"

        return ret

    def open_wallet(self, writable=False):
        self.db = DB(self.db_env)
        flags = DB_THREAD | (DB_CREATE if writable else DB_RDONLY)
        try:
            r = self.db.open(self.name, "main", DB_BTREE, flags)
        except DBError:
            r = True

        if r is not None:
            logging.error("Couldn't open wallet.dat/main. Try quitting Bitcoin and running this again.")
            sys.exit(1)

    def parse_wallet(self):
        for (key, value) in self.db.items():
            d = {}

            kds = BCBytesStream(key)
            vds = BCBytesStream(value)

            t = kds.deser_string()

            d["__key__"] = key
            d["__value__"] = value
            d["__type__"] = t

            try:
                if t == "tx":
                    tx_id = kds.read(32)
                    tx = WalletTransaction()
                    tx.deserialize(vds)
                    tx.tx_id = tx_id
                    self.wallet_transactions.append(tx)
                elif t == "name":
                    self.names[vds.deser_string()] = kds.deser_string()
                elif t == "version":
                    self.version = vds.deser_uint32()
                elif t == "minversion":
                    self.minimum_version = vds.deser_uint32()
                elif t == "orderposnext":
                    self.orderposnext = vds.deser_int64()
                elif t == "key":
                    public_key = kds.read(kds.deser_compact_size())
                    private_key = vds.read(vds.deser_compact_size())
                    self.keys[public_key]: TODO
                    self.owner_keys[public_key_to_bc_address(public_key)] = private_key
                elif t == "wkey":
                    public_key = kds.read(kds.deser_compact_size())
                    private_key = vds.read(vds.deser_compact_size())
                    created = vds.deser_int64()
                    expires = vds.deser_int64()
                    comment = vds.deser_string()
                    self.wkeys.append({'pubkey': public_key, 'priv_key': private_key, 'created': created, 'expiers': expires, 'comment': comment})
                elif t == "defaultkey":
                    self.default_key = vds.read(vds.deser_compact_size())
                elif t == "bestblock":
                    best_block = BlockLocator()
                    best_block.deserialize(vds)
                    self.best_block = best_block
                elif t == "bestblock_nomerkle":
                    best_block_no_merkle = BlockLocator()
                    best_block_no_merkle.deserialize(vds)
                    self.best_block_no_merkle = best_block_no_merkle
                elif t == "purpose":
                    self.purposes[kds.deser_string()] = vds.deser_string()
                elif t == "pool":
                    keypool = KeyPool()
                    keypool.deserialize(vds)
                    self.pool[kds.deser_int64()] = keypool
                elif t == "acc":
                    account = Account()
                    account.deserialize(vds)
                    self.accounts[kds.deser_string()] = account
                elif t == "hdchain":
                    hd_chain = HDChain()
                    hd_chain.deserialize(vds)
                    self.hd_chain = hd_chain
                elif t == "acentry":
                    account_entry = AccountingEntry()
                    account_entry.deserialize(vds)
                    account_entry.account = kds.deser_string()
                    account_entry.index = kds.deser_uint64()
                    self.accounting_entries.append(account_entry)
                elif t == "keymeta":
                    key_metadata = KeyMeta()
                    key_metadata.deserialize(vds)
                    self.key_meta.append(key_metadata)
                else:
                    print("ERROR parsing wallet.dat, type %s" % t)
                    self.records.append(d)

            except Exception as e:
                print("ERROR parsing wallet.dat, type %s" % t)
                print("key data in hex: {}".format(key.hex()))
                print("value data in hex: {}".format(value.hex()))
                raise

        self.wallet_transactions.sort(key=lambda i: i.time_received)
        self.key_meta.sort(key=lambda i: i.hd_key_path)

    def close(self):
        """Close the database and database environment."""
        self.db.close()

        self.db_env.close()

def dump_wallet(wallet, print_wallet, print_wallet_transactions):

    if print_wallet:
        print(wallet)
        for d in wallet.records:
            print("Unknown key type: {}".format(d["__type__"]))
            print("value data in hex: {}".format(d["__value__"]))

    if print_wallet_transactions:
        print("wallet transactions:")
        print("  \n".join(["  {}".format(tx) for tx in wallet.wallet_transactions]))
