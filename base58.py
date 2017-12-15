#!/usr/bin/env python3
#
# Copyright (c) 2010 Gavin Andresen
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""encode/decode base58 in the same way that Bitcoin does"""

import hashlib

__b58chars = '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz'
__b58base = len(__b58chars)

def b58encode(v):
    """ encode v, which is a string of bytes, to base58."""

    long_value = 0
    for (i, c) in enumerate(v[::-1]):
        long_value += (256**i) * c

    result = ''
    while long_value >= __b58base:
        div, mod = divmod(long_value, __b58base)
        result = __b58chars[mod] + result
        long_value = div
    result = __b58chars[long_value] + result

    # Bitcoin does a little leading-zero-compression:
    # leading 0-bytes in the input become leading-1s
    pad = 0
    for c in v:
        if c == '\0':
            pad += 1
        else:
            break

    return (__b58chars[0] * pad) + result

def b58decode(v, length):
    """ decode v into a string of len bytes"""
    long_value = 0
    for (i, c) in enumerate(v[::-1]):
        long_value += __b58chars.find(c) * (__b58base**i)

    result = ''
    while long_value >= 256:
        div, mod = divmod(long_value, 256)
        result = chr(mod) + result
        long_value = div
    result = chr(long_value) + result

    pad = 0
    for c in v:
        if c == __b58chars[0]:
            pad += 1
        else:
            break

    result = chr(0) * pad + result
    if length is not None and len(result) != length:
        return None

    return result

def hash_160(public_key):
    h1 = hashlib.new('sha256', public_key).digest()
    h2 = hashlib.new('ripemd160', h1).digest()
    return h2

def public_key_to_bc_address(public_key):
    h160 = hash_160(public_key)
    return hash_160_to_bc_address(h160)

def hash_160_to_bc_address(h160):
    vh160 = b"\x00" + h160  # \x00 is version 0
    h3 = hashlib.new('sha256', hashlib.new('sha256', vh160).digest()).digest()
    addr = vh160 + h3[0:4]
    return b58encode(addr)

def bc_address_to_hash_160(addr):
    bytes = b58decode(addr, 25)
    return bytes[1:21]

if __name__ == '__main__':
    x = '005cc87f4a3fdfe3a2346b6953267ca867282630d3f9b78e64'.decode('hex_codec')
    encoded = b58encode(x)
    print(encoded, '19TbMSWwHvnxAKy12iNm3KdbGfzfaMFViT')
    print(b58decode(encoded, len(x)).encode('hex_codec'), x.encode('hex_codec'))
