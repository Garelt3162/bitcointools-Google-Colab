#!/usr/bin/env python3
#
# Copyright (c) 2017 John Newbery
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""Deserialize banlist.dat file."""
import os.path

from BCDataStream import BCDataStream
from datastructures import Ban
from deserialize import deserialize_magic

class Banlist():
    """Represents contents of banlist.dat file."""
    def __init__(self):
        self.magic = b''
        self.network = b''
        self.banmap = {}

    def deserialize(self, f):
        self.magic, self.network = deserialize_magic(f)
        bl_len = f.read_compact_size()

        for _ in range(bl_len):
            ban = Ban()
            ban.deserialize(f)

            self.banmap[ban.subnet] = ban.ban_entry

    def __repr__(self):
        ret = "Network magic: 0x{} ({})\n".format(self.magic.hex(), self.network)
        if self.banmap:
            ret += "ban entries:\n"
        for subnet, ban in self.banmap.items():
            ret += "   [{}]: {}".format(subnet.__repr__(), ban.__repr__())

        return ret

def dump_banlist(datadir):
    banlist_file = os.path.join(datadir, "banlist.dat")

    banlist_ds = BCDataStream()
    banlist_ds.clear()

    with open(banlist_file, "rb") as f:
        banlist_ds.write(f.read())

    banlist = Banlist()
    banlist.deserialize(banlist_ds)

    print(banlist)
