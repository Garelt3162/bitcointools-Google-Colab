#!/usr/bin/env python3
#
# Copyright (c) 2010 Gavin Andresen
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""Code for parsing the wallet.dat file"""

from base58 import public_key_to_bc_address
import logging
import sys
import time

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

from datastructures import WalletTransaction, BestBlock, KeyPool
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
    """Represents contents of wallet.dat file."""

    def __init__(self, datadir):
        self.default_key = b''
        self.keys = {}
        self.minimum_version = 0
        self.names = {}
        self.orderposnext = 0
        self.owner_keys = {}
        self.pool = {}
        self.purposes = {}
        self.records = []
        self.transaction_index = {}
        self.version = 0
        self.wallet_transactions = []
        self.wkeys = {}

        try:
            self.db_env = create_env(datadir)
        except DBNoSuchFileError:
            logging.error("Couldn't open " + datadir)
            sys.exit(1)

        self.open_wallet(self.db_env)

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
            ret += "KeyPool:\n"
            ret += "".join(["  {}. {}".format(n, key_pool) for n, key_pool in self.pool.items()])

        return ret

    def open_wallet(self, writable=False):
        self.db = DB(self.db_env)
        flags = DB_THREAD | (DB_CREATE if writable else DB_RDONLY)
        try:
            r = self.db.open("wallet.dat", "main", DB_BTREE, flags)
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
                    self.transaction_index[tx_id] = tx
                    continue
                if t == "name":
                    self.names[vds.deser_string()] = kds.deser_string()
                    continue
                elif t == "version":
                    self.version = vds.deser_uint32()
                    continue
                elif t == "minversion":
                    self.minimum_version = vds.deser_uint32()
                    continue
                elif t == "orderposnext":
                    self.orderposnext = vds.deser_int64()
                    continue
                elif t == "key":
                    public_key = kds.read(kds.deser_compact_size())
                    private_key = vds.read(vds.deser_compact_size())
                    self.keys[public_key] = private_key
                    self.owner_keys[public_key_to_bc_address(public_key)] = private_key
                    continue
                elif t == "wkey":
                    public_key = kds.read(kds.deser_compact_size())
                    private_key = vds.read(vds.deser_compact_size())
                    created = vds.deser_int64()
                    expires = vds.deser_int64()
                    comment = vds.deser_string()
                    self.wkeys.append({'pubkey': public_key, 'priv_key': private_key, 'created': created, 'expiers': expires, 'comment': comment})
                    continue
                elif t == "defaultkey":
                    self.default_key = vds.read(vds.deser_compact_size())
                    continue
                elif t == "bestblock":
                    best_block = BestBlock()
                    best_block.deserialize(vds)
                    self.best_block = best_block
                    continue
                elif t == "bestblock_nomerkle":
                    best_block_no_merkle = BestBlock()
                    best_block_no_merkle.deserialize(vds)
                    self.best_block_no_merkle = best_block_no_merkle
                    continue
                elif t == "purpose":
                    self.purposes[kds.deser_string()] = vds.deser_string()
                    continue
                elif t == "pool":
                    keypool = KeyPool()
                    keypool.deserialize(vds)
                    self.pool[kds.deser_int64()] = keypool
                    continue
                # elif t == "acc":
                #     d['account'] = kds.deser_string()
                #     d['nVersion'] = vds.read_int32()
                #     d['public_key'] = vds.read(vds.read_compact_size())
                # elif t == "acentry":
                #     d['account'] = kds.deser_string()
                #     d['n'] = kds.read_uint64()
                #     d['nVersion'] = vds.read_int32()
                #     d['nCreditDebit'] = vds.read_int64()
                #     d['nTime'] = vds.read_int64()
                #     d['otherAccount'] = vds.deser_string()
                #     d['comment'] = vds.deser_string()
                # elif t == "hdchain":
                #     d['nVersion'] = vds.read_uint32()
                #     d['nExternalChainCounter'] = vds.read_uint32()
                #     d['masterKeyID'] = vds.read(20).hex()
                #     d['nInternalChainCounter'] = "No internal chain"
                #     if d['nVersion'] >= VERSION_HD_CHAIN_SPLIT:
                #         d['nInternalChainCounter'] = vds.read_uint32()
                # elif t == "keymeta":
                #     d['nVersion'] = vds.read_uint32()
                #     d['nCreateTime'] = vds.read_int64()
                #     if d['nVersion'] >= VERSION_WITH_HDDATA:
                #         d['hdKeyPath'] = vds.deser_string()
                #         d['hdMasterKeyID'] = vds.read(20).hex()
                #     else:
                #         d['hdKeyPath'] = "Not HD"
                #         d['hdMasterKeyID'] = "Not HD"
                else:
                    print("ERROR parsing wallet.dat, type %s" % t)
                    continue

                self.records.append(d)

            except Exception as e:
                print("ERROR parsing wallet.dat, type %s" % t)
                print("key data in hex: {}".format(key.hex()))
                print("value data in hex: {}".format(value.hex()))
                raise

    def close(self):
        """Close the database and database environment."""
        self.db.close()

        self.db_env.close()

def dump_wallet(wallet, print_wallet, print_wallet_transactions, transaction_filter):

    if print_wallet:
        print(wallet)
        for d in wallet.records:
            t = d["__type__"]

            if t == "acc":
                print("Account: {}, current key: {}".format(d['account'], public_key_to_bc_address(d['public_key'])))
            elif t == "acentry":
                print("Move {} {} (other: '{}', time: {}, entry {}) {}".format((d['account'], d['nCreditDebit'], d['otherAccount'], time.ctime(d['nTime']), d['n'], d['comment'])))
            elif t == "hdchain":
                print("hdchain: version: {}, external chain counter:{}, master key id: {}, internal chain counter: {}".format(d['nVersion'], d['nExternalChainCounter'], d['masterKeyID'], d['nInternalChainCounter']))
            elif t == "keymeta":
                print("keymeta: version: {}, create time: {}, HD key path: {}, HD master key: {}".format(d['nVersion'], time.ctime(d['nCreateTime']), d['hdKeyPath'], d['hdMasterKeyID']))
            else:
                print("Unknown key type: {}".format(t.hex()))
                print("value data in hex: {}".format(d["__value__"]))
                pass

    if print_wallet_transactions:
        for tx in sorted(wallet.wallet_transactions, key=lambda i: i.time_received):
            # tx_value = deserialize_wallet_tx(d, wallet.transaction_index, wallet.owner_keys)
            # if len(transaction_filter) > 0 and re.search(transaction_filter, tx_value) is None:
            #     continue

            print("==WalletTransaction== {}".format(tx.tx_id[::-1].hex()))
            print(tx)


# def dump_accounts(wallet):
#     accounts = set()

#     for d in wallet.records:
#         t = d["__type__"]
#         if t == "acc":
#             accounts.add(d['account'])
#         elif t == "name":
#             accounts.add(d['name'])
#         elif t == "acentry":
#             accounts.add(d['account'])
#             # Note: don't need to add otheraccount, because moves are
#             # always double-entry

#     for name in sorted(accounts):
#         print(name)

# def update_wallet(db, t, data):
#     """Write a single item to the wallet.
#     db must be open with writable=True.
#     t and data are the type code and data dictionary as parse_wallet would
#     give to item_callback.
#     data's __key__, __value__ and __type__ are ignored; only the primary data
#     fields are used.
#     """
#     d = data
#     kds = BCDataStream()
#     vds = BCDataStream()

#     # Write the type code to the key
#     kds.write_string(t)
#     vds.write("")             # Ensure there is something

#     try:
#         if t == "tx":
#             raise NotImplementedError("Writing items of type 'tx'")
#             kds.write(d['tx_id'])
#             # d.update(parse_wallet_tx(vds))
#         elif t == "name":
#             kds.write(d['hash'])
#             vds.write(d['name'])
#         elif t == "version":
#             vds.write_uint32(d['version'])
#         elif t == "setting":
#             raise NotImplementedError("Writing items of type 'setting'")
#             kds.write_string(d['setting'])
#             # d['value'] = parse_setting(d['setting'], vds)
#         elif t == "key":
#             kds.write_string(d['public_key'])
#             vds.write_string(d['private_key'])
#         elif t == "wkey":
#             kds.write_string(d['public_key'])
#             vds.write_string(d['private_key'])
#             vds.write_int64(d['created'])
#             vds.write_int64(d['expires'])
#             vds.write_string(d['comment'])
#         elif t == "defaultkey":
#             vds.write_string(d['key'])
#         elif t == "pool":
#             kds.write_int64(d['n'])
#             vds.write_int32(d['nVersion'])
#             vds.write_int64(d['nTime'])
#             vds.write_string(d['public_key'])
#         elif t == "acc":
#             kds.write_string(d['account'])
#             vds.write_int32(d['nVersion'])
#             vds.write_string(d['public_key'])
#         elif t == "acentry":
#             kds.write_string(d['account'])
#             kds.write_uint64(d['n'])
#             vds.write_int32(d['nVersion'])
#             vds.write_int64(d['nCreditDebit'])
#             vds.write_int64(d['nTime'])
#             vds.write_string(d['otherAccount'])
#             vds.write_string(d['comment'])
#         else:
#             print("Unknown key type: " + t)

#         # Write the key/value pair to the database
#         db.put(kds.input, vds.input)

#     except Exception as e:
#         print("ERROR writing to wallet.dat, type %s" % t)
#         print("data dictionary: %r" % data)

# def rewrite_wallet(db_env, dest_filename, pre_put_callback=None):
#     db = open_wallet(db_env)

#     db_out = DB(db_env)
#     try:
#         r = db_out.open(dest_filename, "main", DB_BTREE, DB_CREATE)
#     except DBError:
#         r = True

#     if r is not None:
#         logging.error("Couldn't open %s." % dest_filename)
#         sys.exit(1)

#     def item_callback(t, d):
#         if (pre_put_callback is None or pre_put_callback(t, d)):
#             db_out.put(d["__key__"], d["__value__"])

#     parse_wallet(db, item_callback)

#     db_out.close()
#     db.close()

# def trim_wallet(wallet, dest_filename, pre_put_callback=None):
#     """Write out ONLY address book public/private keys
#        THIS WILL NOT WRITE OUT 'change' KEYS-- you should
#        send all of your bitcoins to one of your public addresses
#        before calling this."""
#     pubkeys = []

#     def gather_pubkeys(t, d):
#         if t == "name":
#             pubkeys.append(bc_address_to_hash_160(d['hash']))

#     wallet.parse_wallet()

#     db_out = DB(db_env)
#     try:
#         r = db_out.open(dest_filename, "main", DB_BTREE, DB_CREATE)
#     except DBError:
#         r = True

#     if r is not None:
#         logging.error("Couldn't open %s." % dest_filename)
#         sys.exit(1)

#     def item_callback(t, d):
#         should_write = False
#         if t in ['version', 'name', 'acc']:
#             should_write = True
#         if t in ['key', 'wkey'] and hash_160(d['public_key']) in pubkeys:
#             should_write = True
#         if pre_put_callback is not None:
#             should_write = pre_put_callback(t, d, pubkeys)
#         if should_write:
#             db_out.put(d["__key__"], d["__value__"])

#     parse_wallet(db, item_callback)

#     db_out.close()
#     db.close()
