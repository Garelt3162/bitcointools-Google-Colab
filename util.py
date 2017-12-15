#!/usr/bin/env python3
#
# Copyright (c) 2010 Gavin Andresen
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""Misc util routines."""

import os
import os.path
import platform

from bsddb3.db import (  # pip3 install bsddb3
    DBEnv,
    DB_CREATE,
    DB_INIT_LOCK,
    DB_INIT_LOG,
    DB_INIT_MPOOL,
    DB_INIT_TXN,
    DB_THREAD,
    DB_RECOVER,
)

def short_hex(b):
    t = b.hex()
    if len(t) < 11:
        return t
    return t[:7] + "..."

def determine_db_dir():
    if platform.system() == "Darwin":
        return os.path.expanduser("~/Library/Application Support/Bitcoin/")
    elif platform.system() == "Windows":
        return os.path.join(os.environ['APPDATA'], "Bitcoin")
    return os.path.expanduser("~/.bitcoin")

def create_env(db_dir=None):
    if db_dir is None:
        db_dir = determine_db_dir()
    db_env = DBEnv(0)
    db_env.open(db_dir, DB_CREATE | DB_INIT_LOCK | DB_INIT_LOG | DB_INIT_MPOOL | DB_INIT_TXN | DB_THREAD | DB_RECOVER)
    return db_env
