#!/usr/bin/env python3
#
# Copyright (c) 2010 Gavin Andresen
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
""" Code for parsing the addr.dat file

NOTE: I think you have to shutdown the Bitcoin client to
successfully read addr.dat..."""

import logging
import sys

from bsddb3.db import (  # pip3 install bsddb3
    DB,
    DBError,
    DB_BTREE,
    DB_THREAD,
    DB_RDONLY,
)

from BCDataStream import BCDataStream
from deserialize import parse_address, deserialize_address

def dump_addresses(db_env):
    db = DB(db_env)
    try:
        r = db.open("addr.dat", "main", DB_BTREE, DB_THREAD | DB_RDONLY)
    except DBError:
        r = True

    if r is not None:
        logging.error("Couldn't open addr.dat/main. Try quitting Bitcoin and running this again.")
        sys.exit(1)

    kds = BCDataStream()
    vds = BCDataStream()

    for (key, value) in db.items():
        kds.clear()
        kds.write(key)
        vds.clear()
        vds.write(value)

        type = kds.read_string()

        if type == "addr":
            d = parse_address(vds)
            print(deserialize_address(d))

    db.close()
