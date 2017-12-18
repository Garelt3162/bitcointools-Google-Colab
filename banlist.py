#!/usr/bin/env python3
#
# Copyright (c) 2017 John Newbery
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""Deserialize banlist.dat file."""
import os.path

from datastructures import Ban
import deserialize as des
from util import hash256

class Banlist():
    """Represents contents of banlist.dat file."""
    def __init__(self):
        self.magic = b''
        self.network = b''
        self.banmap = {}

    def deserialize(self, f):
        self.magic, self.network = des.deserialize_magic(f)
        bl_len = des.deser_compact_size(f)

        for _ in range(bl_len):
            ban = Ban()
            ban.deserialize(f)

            self.banmap[ban.subnet] = ban.ban_entry

        # Verify the checksum
        position = f.tell()
        f.seek(0)
        if hash256(f.read(position)) != f.read(32):
            raise des.SerializationError("File checksum incorrect")

    def __repr__(self):
        ret = "Network magic: 0x{} ({})\n".format(self.magic.hex(), self.network)
        if self.banmap:
            ret += "ban entries:\n"
        for subnet, ban in self.banmap.items():
            ret += "   [{}]: {}".format(subnet.__repr__(), ban.__repr__())

        return ret

def dump_banlist(datadir):
    banlist = Banlist()

    banlist_file = os.path.join(datadir, "banlist.dat")

    with open(banlist_file, "rb") as f:
        banlist.deserialize(f)

    print(banlist)
