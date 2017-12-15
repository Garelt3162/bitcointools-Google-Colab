#!/usr/bin/env python3
#
# Copyright (c) 2010 Gavin Andresen
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""Misc util routines."""

from bsddb3.db import *  # pip3 install bsddb3

def long_hex(bytes):
  return bytes.encode('hex_codec')

def short_hex(bytes):
  t = bytes.encode('hex_codec')
  if len(t) < 11:
    return t
  return t[0:4]+"..."+t[-4:]

def determine_db_dir():
  import os
  import os.path
  import platform
  if platform.system() == "Darwin":
    return os.path.expanduser("~/Library/Application Support/Bitcoin/")
  elif platform.system() == "Windows":
    return os.path.join(os.environ['APPDATA'], "Bitcoin")
  return os.path.expanduser("~/.bitcoin")

def create_env(db_dir=None):
  if db_dir is None:
    db_dir = determine_db_dir()
  db_env = DBEnv(0)
  r = db_env.open(db_dir,
                  (DB_CREATE|DB_INIT_LOCK|DB_INIT_LOG|DB_INIT_MPOOL|
                   DB_INIT_TXN|DB_THREAD|DB_RECOVER))
  return db_env
