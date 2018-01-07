#!/usr/bin/env python3
#
# Copyright (c) 2010 Gavin Andresen
# Copyright (c) 2018 John Newbery
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""encode/decode base58 addresses.

TODO: add decoding of base58 addresses.
TODO: add encoding/decoding of bech32 addresses."""
from util import hash160, hash256

B58_CHARSET = '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz'
assert len(B58_CHARSET) == 58

def bytes_to_base58(bs):
    """Convert a byte array to a base58 string."""

    # Convert to an int
    v = int.from_bytes(bs, 'big')

    result = ''
    while v >= 1:
        v, mod = divmod(v, 58)
        result = B58_CHARSET[mod] + result

    # Leading-zero-compression:
    # leading 0-bytes in the input become leading 1s
    while (bs[:2] == '00'):
        result = B58_CHARSET[0] + result
        bs = bs[2:]

    return result

def public_key_to_bc_address(public_key):
    """Return the base58 address for a public key."""

    # RIPEMD160(SHA256()) the pubkey
    h160 = hash160(public_key)

    # Prepend version (0 for P2PKH)
    vh160 = b"\x00" + h160

    # Calculate and postpend the checksum
    h3 = hash256(vh160)
    addr = vh160 + h3[0:4]

    # Convert the byte array to base58 and return
    return bytes_to_base58(addr)
