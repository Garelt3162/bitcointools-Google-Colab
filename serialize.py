#!/usr/bin/env python3
#
# Copyright (c) 2017 John Newbery
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.

from contextlib import contextmanager
from io import BufferedReader
import struct

class BCBytesStream():
    """A class that provides additional serialization and deserialization methods
    over a base BufferedReader class.

    The BufferedReader object is class member _br and all unknown method
    calls are passed to _br"""

    def __init__(self, br):
        """Must be initialized with a BufferedReader."""
        assert type(br) == BufferedReader
        self._br = br

    def __getattr__(self, name):
        return getattr(self._br, name)

    def deser_boolean(self, f):
        return struct.unpack("?", f.read(1))[0]

    def ser_boolean(self, l):
        return struct.pack("?", l)

    def deser_int8(self, f):
        return struct.unpack("<b", f.read(1))[0]

    def ser_int8(self, l):
        return struct.pack("<b", l)

@contextmanager
def open_bs(path, mode):
    """Open a new BCBytesStream."""
    try:
        f = open(path, mode + 'b')
        yield BCBytesStream(f)
    finally:
        f.close()
