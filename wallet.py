#!/usr/bin/env python3
#
# Copyright (c) 2010 Gavin Andresen
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""Code for parsing the wallet.dat file"""

import logging
import re
import sys
import time

from bsddb3.db import (  # pip3 install bsddb3
    DB,
    DBError,
    DB_BTREE,
    DB_CREATE,
    DB_THREAD,
    DB_RDONLY,
)

from base58 import public_key_to_bc_address, bc_address_to_hash_160, hash_160
from deserialize import (
    parse_wallet_tx,
    deserialize_wallet_tx,
    parse_setting,
)
from BCDataStream import BCDataStream
from util import short_hex

def open_wallet(db_env, writable=False):
    db = DB(db_env)
    flags = DB_THREAD | (DB_CREATE if writable else DB_RDONLY)
    try:
        r = db.open("wallet.dat", "main", DB_BTREE, flags)
    except DBError:
        r = True

    if r is not None:
        logging.error("Couldn't open wallet.dat/main. Try quitting Bitcoin and running this again.")
        sys.exit(1)

    return db

def parse_wallet(db):
    kds = BCDataStream()
    vds = BCDataStream()

    records = []

    for (key, value) in db.items():
        d = {}

        kds.clear()
        kds.write(key)
        vds.clear()
        vds.write(value)

        t = kds.read_string()

        d["__key__"] = key
        d["__value__"] = value
        d["__type__"] = t

        try:
            if t == "tx":
                d["tx_id"] = kds.read_bytes(32)
                d.update(parse_wallet_tx(vds))
            elif t == "name":
                d['hash'] = kds.read_string()
                d['name'] = vds.read_string()
            elif t == "version":
                d['version'] = vds.read_uint32()
            elif t == "setting":
                d['setting'] = kds.read_string()
                d['value'] = parse_setting(d['setting'], vds)
            elif t == "key":
                d['public_key'] = kds.read_bytes(kds.read_compact_size())
                d['private_key'] = vds.read_bytes(vds.read_compact_size())
            elif t == "wkey":
                d['public_key'] = kds.read_bytes(kds.read_compact_size())
                d['private_key'] = vds.read_bytes(vds.read_compact_size())
                d['created'] = vds.read_int64()
                d['expires'] = vds.read_int64()
                d['comment'] = vds.read_string()
            elif t == "defaultkey":
                d['key'] = vds.read_bytes(vds.read_compact_size())
            elif t == "pool":
                d['n'] = kds.read_int64()
                d['nVersion'] = vds.read_int32()
                d['nTime'] = vds.read_int64()
                d['public_key'] = vds.read_bytes(vds.read_compact_size())
            elif t == "acc":
                d['account'] = kds.read_string()
                d['nVersion'] = vds.read_int32()
                d['public_key'] = vds.read_bytes(vds.read_compact_size())
            elif t == "acentry":
                d['account'] = kds.read_string()
                d['n'] = kds.read_uint64()
                d['nVersion'] = vds.read_int32()
                d['nCreditDebit'] = vds.read_int64()
                d['nTime'] = vds.read_int64()
                d['otherAccount'] = vds.read_string()
                d['comment'] = vds.read_string()
            elif t == "bestblock_nomerkle":
                d['nVersion'] = vds.read_uint32()
                d['vHave'] = []
                for block in range(vds.read_compact_size()):
                    d['vHave'].append(vds.read_bytes(32).hex())
            elif t == "bestblock":
                d['nVersion'] = vds.read_uint32()
                d['vHave'] = []
                for block in range(vds.read_compact_size()):
                    d['vHave'].append(vds.read_bytes(32).hex())
            elif t == "minversion":
                d['nVersion'] = vds.read_uint32()
            elif t == "hdchain":
                VERSION_HD_CHAIN_SPLIT = 2
                d['nVersion'] = vds.read_uint32()
                d['nExternalChainCounter'] = vds.read_uint32()
                d['masterKeyID'] = vds.read_bytes(20).hex()
                d['nInternalChainCounter'] = "No internal chain"
                if d['nVersion'] >= VERSION_HD_CHAIN_SPLIT:
                    d['nInternalChainCounter'] = vds.read_uint32()
            elif t == "keymeta":
                VERSION_WITH_HDDATA = 10
                d['nVersion'] = vds.read_uint32()
                d['nCreateTime'] = vds.read_int64()
                if d['nVersion'] >= VERSION_WITH_HDDATA:
                    d['hdKeyPath'] = vds.read_string()
                    d['hdMasterKeyID'] = vds.read_bytes(20).hex()
                else:
                    d['hdKeyPath'] = "Not HD"
                    d['hdMasterKeyID'] = "Not HD"

            records.append(d)

        except Exception as e:
            print("ERROR parsing wallet.dat, type %s" % t)
            print("key data in hex: {}".format(key))
            print("value data in hex: {}".format(value))
            raise

    return records

def dump_wallet(db_env, print_wallet, print_wallet_transactions, transaction_filter):
    db = open_wallet(db_env)

    wallet_transactions = []
    transaction_index = {}
    owner_keys = {}

    records = parse_wallet(db)

    for d in records:
        t = d["__type__"]
        if t == "tx":
            wallet_transactions.append(d)
            transaction_index[d['tx_id']] = d
        elif t == "key":
            owner_keys[public_key_to_bc_address(d['public_key'])] = d['private_key']

        if not print_wallet:
            return
        if t == "tx":
            return
        elif t == "name":
            print("address {} : {}".format(d['hash'], d['name']))
        elif t == "version":
            print("version: {}".format(d['version']))
        elif t == "setting":
            print("setting {}: {}".format(d['setting'], str(d['value'])))
        elif t == "key":
            print("Public key: {}, address: {}, private key: {}".format(d['public_key'].hex(), public_key_to_bc_address(d['public_key']), short_hex(d['private_key'])))
        elif t == "wkey":
            print("WPubKey 0x" + short_hex(d['public_key']) + " " + public_key_to_bc_address(d['public_key']) +
                  ": WPriKey 0x" + short_hex(d['private_key']))
            print(" Created: " + time.ctime(d['created']) + " Expires: " + time.ctime(d['expires']) + " Comment: " + d['comment'])
        elif t == "defaultkey":
            print("Default Key: 0x" + short_hex(d['key']) + " " + public_key_to_bc_address(d['key']))
        elif t == "pool":
            print("Change Pool key %d: %s (Time: %s)" % (d['n'], public_key_to_bc_address(d['public_key']), time.ctime(d['nTime'])))
        elif t == "acc":
            print("Account %s (current key: %s)" % (d['account'], public_key_to_bc_address(d['public_key'])))
        elif t == "acentry":
            print("Move '%s' %d (other: '%s', time: %s, entry %d) %s" %
                  (d['account'], d['nCreditDebit'], d['otherAccount'], time.ctime(d['nTime']), d['n'], d['comment']))
        elif t == "minversion":
            print("minversion: {}".format(d['nVersion']))
        elif t == "bestblock":
            if d['vHave']:
                best_block = d['vHave'][0]
            else:
                best_block = "empty"
            print("bestblock: version:{}, bestblock hash: {}".format(d['nVersion'], best_block))
        elif t == "bestblock_nomerkle":
            if d['vHave']:
                best_block = d['vHave'][0]
            else:
                best_block = "empty"
            print("bestblock_nomerkle: version:{}, bestblock hash: {}".format(d['nVersion'], best_block))
        elif t == "hdchain":
            print("hdchain: version: {}, external chain counter:{}, master key id: {}, internal chain counter: {}".format(d['nVersion'], d['nExternalChainCounter'], d['masterKeyID'], d['nInternalChainCounter']))
        elif t == "keymeta":
            print("keymeta: version: {}, create time: {}, HD key path: {}, HD master key: {}".format(d['nVersion'], time.ctime(d['nCreateTime']), d['hdKeyPath'], d['hdMasterKeyID']))
        else:
            print("Unknown key type: " + t)
            print("value data in hex: {}".format(d["__value__"]))

    if print_wallet_transactions:
        keyfunc = lambda i: i['timeReceived']
        for d in sorted(wallet_transactions, key=keyfunc):
            tx_value = deserialize_wallet_tx(d, transaction_index, owner_keys)
            if len(transaction_filter) > 0 and re.search(transaction_filter, tx_value) is None:
                continue

            print("==WalletTransaction== " + d['tx_id'][::-1]).hex()
            print(tx_value)

    db.close()

def dump_accounts(db_env):
    db = open_wallet(db_env)

    kds = BCDataStream()
    vds = BCDataStream()

    accounts = set()

    for (key, value) in db.items():
        kds.clear()
        kds.write(key)
        vds.clear()
        vds.write(value)

        t = kds.read_string()

        if t == "acc":
            accounts.add(kds.read_string())
        elif t == "name":
            accounts.add(vds.read_string())
        elif t == "acentry":
            accounts.add(kds.read_string())
            # Note: don't need to add otheraccount, because moves are
            # always double-entry

    for name in sorted(accounts):
        print(name)

    db.close()

def update_wallet(db, t, data):
    """Write a single item to the wallet.
    db must be open with writable=True.
    t and data are the type code and data dictionary as parse_wallet would
    give to item_callback.
    data's __key__, __value__ and __type__ are ignored; only the primary data
    fields are used.
    """
    d = data
    kds = BCDataStream()
    vds = BCDataStream()

    # Write the type code to the key
    kds.write_string(t)
    vds.write("")             # Ensure there is something

    try:
        if t == "tx":
            raise NotImplementedError("Writing items of type 'tx'")
            kds.write(d['tx_id'])
            # d.update(parse_wallet_tx(vds))
        elif t == "name":
            kds.write(d['hash'])
            vds.write(d['name'])
        elif t == "version":
            vds.write_uint32(d['version'])
        elif t == "setting":
            raise NotImplementedError("Writing items of type 'setting'")
            kds.write_string(d['setting'])
            # d['value'] = parse_setting(d['setting'], vds)
        elif t == "key":
            kds.write_string(d['public_key'])
            vds.write_string(d['private_key'])
        elif t == "wkey":
            kds.write_string(d['public_key'])
            vds.write_string(d['private_key'])
            vds.write_int64(d['created'])
            vds.write_int64(d['expires'])
            vds.write_string(d['comment'])
        elif t == "defaultkey":
            vds.write_string(d['key'])
        elif t == "pool":
            kds.write_int64(d['n'])
            vds.write_int32(d['nVersion'])
            vds.write_int64(d['nTime'])
            vds.write_string(d['public_key'])
        elif t == "acc":
            kds.write_string(d['account'])
            vds.write_int32(d['nVersion'])
            vds.write_string(d['public_key'])
        elif t == "acentry":
            kds.write_string(d['account'])
            kds.write_uint64(d['n'])
            vds.write_int32(d['nVersion'])
            vds.write_int64(d['nCreditDebit'])
            vds.write_int64(d['nTime'])
            vds.write_string(d['otherAccount'])
            vds.write_string(d['comment'])
        else:
            print("Unknown key type: " + t)

        # Write the key/value pair to the database
        db.put(kds.input, vds.input)

    except Exception as e:
        print("ERROR writing to wallet.dat, type %s" % t)
        print("data dictionary: %r" % data)

def rewrite_wallet(db_env, dest_filename, pre_put_callback=None):
    db = open_wallet(db_env)

    db_out = DB(db_env)
    try:
        r = db_out.open(dest_filename, "main", DB_BTREE, DB_CREATE)
    except DBError:
        r = True

    if r is not None:
        logging.error("Couldn't open %s." % dest_filename)
        sys.exit(1)

    def item_callback(t, d):
        if (pre_put_callback is None or pre_put_callback(t, d)):
            db_out.put(d["__key__"], d["__value__"])

    parse_wallet(db, item_callback)

    db_out.close()
    db.close()

def trim_wallet(db_env, dest_filename, pre_put_callback=None):
    """Write out ONLY address book public/private keys
       THIS WILL NOT WRITE OUT 'change' KEYS-- you should
       send all of your bitcoins to one of your public addresses
       before calling this.
    """
    db = open_wallet(db_env)

    pubkeys = []

    def gather_pubkeys(t, d):
        if t == "name":
            pubkeys.append(bc_address_to_hash_160(d['hash']))

    parse_wallet(db, gather_pubkeys)

    db_out = DB(db_env)
    try:
        r = db_out.open(dest_filename, "main", DB_BTREE, DB_CREATE)
    except DBError:
        r = True

    if r is not None:
        logging.error("Couldn't open %s." % dest_filename)
        sys.exit(1)

    def item_callback(t, d):
        should_write = False
        if t in ['version', 'name', 'acc']:
            should_write = True
        if t in ['key', 'wkey'] and hash_160(d['public_key']) in pubkeys:
            should_write = True
        if pre_put_callback is not None:
            should_write = pre_put_callback(t, d, pubkeys)
        if should_write:
            db_out.put(d["__key__"], d["__value__"])

    parse_wallet(db, item_callback)

    db_out.close()
    db.close()
