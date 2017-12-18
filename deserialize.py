#!/usr/bin/env python3
#
# Copyright (c) 2010 Gavin Andresen
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.

from base58 import public_key_to_bc_address, hash_160_to_bc_address
from enumeration import Enumeration
import hashlib
import socket
import struct
import time

from BCDataStream import SerializationError
from util import short_hex

def deser_boolean(f):
    return struct.unpack("?", f.read(1))[0]

def ser_boolean(l):
    return struct.pack("?", l)

def deser_int8(f):
    return struct.unpack("<b", f.read(1))[0]

def ser_int8(l):
    return struct.pack("<b", l)

def deser_uint8(f):
    return struct.unpack("<B", f.read(1))[0]

def ser_uint8(l, val):
    return struct.pack("<B", l)

def deser_int16(f):
    return struct.unpack("<h", f.read(2))[0]

def ser_int16(l):
    return struct.pack("<h", l)

def deser_uint16(f):
    return struct.unpack("<H", f.read(2))[0]

def ser_uint16(l, val):
    return struct.pack("<H", l)

def deser_int32(f):
    return struct.unpack("<i", f.read(4))[0]

def ser_int32(l, val):
    return struct.pack("<i", l)

def deser_uint32(f):
    return struct.unpack("<I", f.read(4))[0]

def ser_uint32(l, val):
    return struct.pack("<I", l)

def deser_int64(f):
    return struct.unpack("<q", f.read(8))[0]

def ser_int64(l, val):
    return struct.pack("<q", l)

def deser_uint64(f):
    return struct.unpack("<Q", f.read(8))[0]

def ser_uint64(l, val):
    return struct.pack("<Q", l)

def deser_uint256(f):
    r = 0
    for i in range(8):
        t = struct.unpack("<I", f.read(4))[0]
        r += t << (i * 32)
    return r

def ser_uint256(u):
    rs = b""
    for i in range(8):
        rs += struct.pack("<I", u & 0xFFFFFFFF)
        u >>= 32
    return rs

def deser_compact_size(f):
    nit = struct.unpack("<B", f.read(1))[0]
    if nit == 253:
        nit = struct.unpack("<H", f.read(2))[0]
    elif nit == 254:
        nit = struct.unpack("<I", f.read(4))[0]
    elif nit == 255:
        nit = struct.unpack("<Q", f.read(8))[0]
    return nit

def ser_compact_size(l):
    r = b""
    if l < 253:
        r = struct.pack("B", l)
    elif l < 0x10000:
        r = struct.pack("<BH", 253, l)
    elif l < 0x100000000:
        r = struct.pack("<BI", 254, l)
    else:
        r = struct.pack("<BQ", 255, l)
    return r

def deser_string(f):
    nit = deser_compact_size(f)
    return f.read(nit)

def ser_string(s):
    return ser_compact_size(len(s)) + s

def deser_vector(f, c):
    nit = deser_compact_size(f)
    r = []
    for i in range(nit):
        t = c()
        t.deserialize(f)
        r.append(t)
    return r

def ser_vector(l, ser_function_name=None):
    """Serialize a vector object.

    ser_function_name: Allow for an alternate serialization function on the
    entries in the vector."""

    r = ser_compact_size(len(l))
    for i in l:
        if ser_function_name:
            r += getattr(i, ser_function_name)()
        else:
            r += i.serialize()
    return r

def deser_uint256_vector(f):
    nit = deser_compact_size(f)
    r = []
    for i in range(nit):
        t = deser_uint256(f)
        r.append(t)
    return r

def ser_uint256_vector(l):
    r = ser_compact_size(len(l))
    for i in l:
        r += ser_uint256(i)
    return r

def deser_string_vector(f):
    nit = deser_compact_size(f)
    r = []
    for i in range(nit):
        t = deser_string(f)
        r.append(t)
    return r

def ser_string_vector(l):
    r = ser_compact_size(len(l))
    for sv in l:
        r += ser_string(sv)
    return r


def parse_address(vds):
    d = {}
    d['nVersion'] = vds.read_int32()
    d['nTime'] = vds.read_uint32()
    d['nServices'] = vds.read_uint64()
    d['pchReserved'] = vds.read_bytes(12)
    d['ip'] = socket.inet_ntoa(vds.read_bytes(4))
    d['port'] = vds.read_uint16()
    return d

def deserialize_magic(f):
    magic = f.read(4)
    if magic == b'\xf9\xbe\xb4\xd9':
        network = "mainnet"
    elif magic == b'\x0b\x11\x09\x07':
        network = "testnet"
    elif magic == b'\xfa\xbf\xb5\xda':
        network = "regtest"
    else:
        network = "unknown"

    return magic, network

def deserialize_address(d):
    return d['ip'] + ":" + str(d['port']) + " (lastseen: %s)" % (time.ctime(d['nTime']),)

def parse_txin(vds):
    # import pdb; pdb.set_trace()
    d = {}
    d['prevout_hash'] = vds.read_bytes(32)
    d['prevout_n'] = vds.read_uint32()
    d['scriptSig'] = vds.read_bytes(vds.read_compact_size())
    d['sequence'] = vds.read_uint32()
    return d

def deserialize_txin(d, transaction_index=None, owner_keys=None):
    if d['prevout_hash'] == "\x00" * 32:
        result = "TxIn: COIN GENERATED"
        result += " coinbase:" + d['scriptSig'].encode('hex_codec')
    elif transaction_index is not None and d['prevout_hash'] in transaction_index:
        p = transaction_index[d['prevout_hash']]['txOut'][d['prevout_n']]
        result = "TxIn: value: %f" % (p['value'] / 1.0e8,)
        result += " prev(" + d['prevout_hash'][::-1].hex() + ":" + str(d['prevout_n']) + ")"
    else:
        result = "TxIn: prev(" + d['prevout_hash'][::-1].hex() + ":" + str(d['prevout_n']) + ")"
        pk = extract_public_key(d['scriptSig'])
        result += " pubkey: " + pk
        result += " sig: " + decode_script(d['scriptSig'])
    if d['sequence'] < 0xffffffff:
        result += " sequence: " + hex(d['sequence'])
    return result

def parse_txout(vds):
    d = {}
    d['value'] = vds.read_int64()
    d['scriptPubKey'] = vds.read_bytes(vds.read_compact_size())
    return d

def deserialize_txout(d, owner_keys=None):
    result = "TxOut: value: %f" % (d['value'] / 1.0e8,)
    pk = extract_public_key(d['scriptPubKey'])
    result += " pubkey: " + pk
    result += " Script: " + decode_script(d['scriptPubKey'])
    if owner_keys is not None:
        if pk in owner_keys:
            result += " Own: True"
        else:
            result += " Own: False"
    return result

def parse_tx(vds):
    d = {}
    start = vds.read_cursor
    d['version'] = vds.read_int32()
    segwit = False
    if int.from_bytes(vds.peep_byte(), 'big') == 0:
        if int.from_bytes(vds.read_bytes(2), 'big') != 1:
            raise SerializationError("Segwit flag not set to 1")
        segwit = True
    n_vin = vds.read_compact_size()
    d['txIn'] = []
    for i in range(n_vin):
        d['txIn'].append(parse_txin(vds))
    n_vout = vds.read_compact_size()
    d['txOut'] = []
    for i in range(n_vout):
        d['txOut'].append(parse_txout(vds))
    if segwit:
        d['script_witnesses'] = []
        for i in range(n_vin):
            d['script_witnesses'].append(vds.read_string_vector())
    d['lockTime'] = vds.read_uint32()
    end = vds.read_cursor
    hash = hashlib.sha256(hashlib.sha256(vds.input[start:end]).digest()).hexdigest()
    d['hash'] = "".join(reversed([hash[i:i + 2] for i in range(0, len(hash), 2)]))
    return d

def deserialize_tx(d, transaction_index=None, owner_keys=None):
    result = "%d tx in, %d out\n" % (len(d['txIn']), len(d['txOut']))
    for txIn in d['txIn']:
        result += deserialize_txin(txIn, transaction_index) + "\n"
    for txOut in d['txOut']:
        result += deserialize_txout(txOut, owner_keys) + "\n"
    return result

def parse_merkle_tx(vds):
    d = parse_tx(vds)
    d['hashBlock'] = vds.read_bytes(32)
    n_merkle_branch = vds.read_compact_size()
    d['merkleBranch'] = vds.read_bytes(32 * n_merkle_branch)
    d['nIndex'] = vds.read_int32()
    return d

def deserialize_merkle_tx(d, transaction_index=None, owner_keys=None):
    tx = deserialize_tx(d, transaction_index, owner_keys)
    result = "block: " + (d['hashBlock'][::-1]).encode('hex_codec')
    result += " %d hashes in merkle branch\n" % (len(d['merkleBranch']) / 32,)
    return result + tx

def parse_wallet_tx(vds):
    d = parse_merkle_tx(vds)
    n_vtx_prev = vds.read_compact_size()
    d['vtxPrev'] = []
    for i in range(n_vtx_prev):
        d['vtxPrev'].append(parse_merkle_tx(vds))

    d['mapValue'] = {}
    n_map_value = vds.read_compact_size()
    for i in range(n_map_value):
        key = vds.read_string()
        value = vds.read_string()
        d['mapValue'][key] = value
    n_order_form = vds.read_compact_size()
    d['orderForm'] = []
    for i in range(n_order_form):
        first = vds.read_string()
        second = vds.read_string()
        d['orderForm'].append((first, second))
    d['fTimeReceivedIsTxTime'] = vds.read_uint32()
    d['timeReceived'] = vds.read_uint32()
    d['fromMe'] = vds.read_boolean()
    d['spent'] = vds.read_boolean()

    return d

def deserialize_wallet_tx(d, transaction_index=None, owner_keys=None):
    result = deserialize_merkle_tx(d, transaction_index, owner_keys)
    result += "%d vtxPrev txns\n" % (len(d['vtxPrev']),)
    result += "mapValue:" + str(d['mapValue'])
    if len(d['orderForm']) > 0:
        result += "\n" + " orderForm:" + str(d['orderForm'])
    result += "\n" + "timeReceived:" + time.ctime(d['timeReceived'])
    result += " fromMe:" + str(d['fromMe']) + " spent:" + str(d['spent'])
    return result

opcodes = Enumeration("Opcodes", [
    ("OP_0", 0), ("OP_PUSHDATA1", 76), "OP_PUSHDATA2", "OP_PUSHDATA4", "OP_1NEGATE", "OP_RESERVED",
    "OP_1", "OP_2", "OP_3", "OP_4", "OP_5", "OP_6", "OP_7",
    "OP_8", "OP_9", "OP_10", "OP_11", "OP_12", "OP_13", "OP_14", "OP_15", "OP_16",
    "OP_NOP", "OP_VER", "OP_IF", "OP_NOTIF", "OP_VERIF", "OP_VERNOTIF", "OP_ELSE", "OP_ENDIF", "OP_VERIFY",
    "OP_RETURN", "OP_TOALTSTACK", "OP_FROMALTSTACK", "OP_2DROP", "OP_2DUP", "OP_3DUP", "OP_2OVER", "OP_2ROT", "OP_2SWAP",
    "OP_IFDUP", "OP_DEPTH", "OP_DROP", "OP_DUP", "OP_NIP", "OP_OVER", "OP_PICK", "OP_ROLL", "OP_ROT",
    "OP_SWAP", "OP_TUCK", "OP_CAT", "OP_SUBSTR", "OP_LEFT", "OP_RIGHT", "OP_SIZE", "OP_INVERT", "OP_AND",
    "OP_OR", "OP_XOR", "OP_EQUAL", "OP_EQUALVERIFY", "OP_RESERVED1", "OP_RESERVED2", "OP_1ADD", "OP_1SUB", "OP_2MUL",
    "OP_2DIV", "OP_NEGATE", "OP_ABS", "OP_NOT", "OP_0NOTEQUAL", "OP_ADD", "OP_SUB", "OP_MUL", "OP_DIV",
    "OP_MOD", "OP_LSHIFT", "OP_RSHIFT", "OP_BOOLAND", "OP_BOOLOR",
    "OP_NUMEQUAL", "OP_NUMEQUALVERIFY", "OP_NUMNOTEQUAL", "OP_LESSTHAN",
    "OP_GREATERTHAN", "OP_LESSTHANOREQUAL", "OP_GREATERTHANOREQUAL", "OP_MIN", "OP_MAX",
    "OP_WITHIN", "OP_RIPEMD160", "OP_SHA1", "OP_SHA256", "OP_HASH160",
    "OP_HASH256", "OP_CODESEPARATOR", "OP_CHECKSIG", "OP_CHECKSIGVERIFY", "OP_CHECKMULTISIG",
    "OP_CHECKMULTISIGVERIFY",
    ("OP_SINGLEBYTE_END", 0xF0),
    ("OP_DOUBLEBYTE_BEGIN", 0xF000),
    "OP_PUBKEY", "OP_PUBKEYHASH",
    ("OP_INVALIDOPCODE", 0xFFFF),
])

def script_getop(bytes):
    i = 0
    while i < len(bytes):
        vch = None
        opcode = ord(bytes[i])
        i += 1
        if opcode >= opcodes.OP_SINGLEBYTE_END:
            opcode <<= 8
            opcode |= bytes[i]
            i += 1

        if opcode <= opcodes.OP_PUSHDATA4:
            size = opcode
            if opcode == opcodes.OP_PUSHDATA1:
                size = ord(bytes[i])
                i += 1
            elif opcode == opcodes.OP_PUSHDATA2:
                size = struct.unpack_from('<H', bytes, i)
                i += 2
            elif opcode == opcodes.OP_PUSHDATA4:
                size = struct.unpack_from('<I', bytes, i)
                i += 4
            vch = bytes[i:i + size]
            i += size

        yield (opcode, vch)

def script_get_opcode_name(opcode):
    return (opcodes.whatis(opcode)).replace("OP_", "")

def decode_script(bytes):
    result = ''
    for (opcode, vch) in script_getop(bytes):
        if len(result) > 0:
            result += " "
        if opcode <= opcodes.OP_PUSHDATA4:
            result += "%d:" % (opcode,)
            result += short_hex(vch)
        else:
            result += script_get_opcode_name(opcode)
    return result

def match_decoded(decoded, to_match):
    if len(decoded) != len(to_match):
        return False
    for i in range(len(decoded)):
        if to_match[i] == opcodes.OP_PUSHDATA4 and decoded[i][0] <= opcodes.OP_PUSHDATA4:
            continue  # Opcodes below OP_PUSHDATA4 all just push data onto stack, and are equivalent.
        if to_match[i] != decoded[i][0]:
            return False
    return True

def extract_public_key(bytes):
    decoded = [x for x in script_getop(bytes)]

    # non-generated TxIn transactions push a signature
    # (seventy-something bytes) and then their public key
    # (65 bytes) onto the stack:
    match = [opcodes.OP_PUSHDATA4, opcodes.OP_PUSHDATA4]
    if match_decoded(decoded, match):
        return public_key_to_bc_address(decoded[1][1])

    # The Genesis Block, self-payments, and pay-by-IP-address payments look like:
    # 65 BYTES:... CHECKSIG
    match = [opcodes.OP_PUSHDATA4, opcodes.OP_CHECKSIG]
    if match_decoded(decoded, match):
        return public_key_to_bc_address(decoded[0][1])

    # Pay-by-Bitcoin-address TxOuts look like:
    # DUP HASH160 20 BYTES:... EQUALVERIFY CHECKSIG
    match = [opcodes.OP_DUP, opcodes.OP_HASH160, opcodes.OP_PUSHDATA4, opcodes.OP_EQUALVERIFY, opcodes.OP_CHECKSIG]
    if match_decoded(decoded, match):
        return hash_160_to_bc_address(decoded[2][1])

    return "(None)"
