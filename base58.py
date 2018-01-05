#!/usr/bin/env python3
#
# Copyright (c) 2010 Gavin Andresen
# Copyright (c) 2018 John Newbery
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""encode/decode base58 addresses.

TODO: add encoding of bech32 addresses."""
from util import hash160, hash256

B58_CHARSET = '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz'
assert len(B58_CHARSET) == 58

def bytes_to_base58(bs):
    """Convert a byte array to a base58 string."""

    # Convert to an int
    v = int.from_bytes(bs, 'big')

    result = ''
    while v >= 0:
        v, mod = divmod(v, 58)
        result = B58_CHARSET[mod] + result

    # Leading-zero-compression:
    # leading 0-bytes in the input become leading 1s
    while (bs[:2] == '00'):
        result = B58_CHARSET[0] + result
        bs = bs[2:]

    return result

# def b58decode(v, length):
#     """ decode v into a string of len bytes"""
#     long_value = 0
#     for (i, c) in enumerate(v[::-1]):
#         long_value += B58_CHARSET.find(c) * (58**i)

#     result = ''
#     while long_value >= 256:
#         div, mod = divmod(long_value, 256)
#         result = chr(mod) + result
#         long_value = div
#     result = chr(long_value) + result

#     pad = 0
#     for c in v:
#         if c == B58_CHARSET[0]:
#             pad += 1
#         else:
#             break

#     result = chr(0) * pad + result
#     if length is not None and len(result) != length:
#         return None

#     return result

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
