#!/usr/bin/env python3
#
# Copyright (c) 2018 John Newbery
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""Test base58.py"""

from binascii import unhexlify
import unittest

import base58

# Test vectors imported from
# https://github.com/bitcoin/bitcoin/blob/b5e4b9b5100ec15217d43edb5f4149439f4b20a5/src/test/data/base58_encode_decode.json
TEST_CASES = [
    ["", ""],
    ["61", "2g"],
    ["626262", "a3gV"],
    ["636363", "aPEr"],
    ["73696d706c792061206c6f6e6720737472696e67", "2cFupjhnEsSn59qHXstmK2ffpLv2"],
    ["00eb15231dfceb60925886b67d065299925915aeb172c06647", "1NS17iag9jJgTHD1VXjvLCEnZuQ3rJDE9L"],
    ["00cf00816e4be7dbc1c3df0c2b0be2b77e4ad99a14111e6c6f", "1KsXUqbYDGz5gvBL2mo6as5KqKueRWc2Wr"],
    ["516b6fcd0f", "ABnLTmg"],
    ["bf4f89001e670274dd", "3SEo3LWLoPntC"],
    ["572e4794", "3EFU7m"],
    ["ecac89cad93923c02321", "EJDM8drfXA6uyA"],
    ["10c8511e", "Rt5zm"],
    ["00000000000000000000", "1111111111"]
]

class Base58TestCase(unittest.TestCase):
    def test_bytes_to_base58(self):
        for input_hex, expected_base58 in TEST_CASES:
            input_bin = unhexlify(input_hex)
            actual_base58 = base58.bytes_to_base58(input_bin)
            self.assertEqual(actual_base58, expected_base58)

    # TODO: test base58 decoding
