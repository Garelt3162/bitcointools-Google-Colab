#!/usr/bin/env python3
#
# Copyright (c) 2017 John Newbery
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
from codecs import encode
import copy
from enum import Enum
import time

from serialize import SerializationError, BCBytesStream
from util import bytes_to_hex_str, hash256

class BanReason(Enum):
    UNKNOWN = 0
    NODE_MISBEHAVING = 1
    MANUALLY_ADDED = 2

COIN = 10 ** 8

VERSION_HD_CHAIN_SPLIT = 2
VERSION_WITH_HDDATA = 10

class OutPoint():
    """Points to a unique transaction output.

    hash: the txid of the transaction
    n: the index of the output amongst all the transactions outputs."""
    def __init__(self, hash=0, n=0):
        self.hash = hash
        self.n = n

    def __repr__(self):
        return "OutPoint(hash=%064x n=%i)" % (self.hash, self.n)

    def deserialize(self, f):
        self.hash = f.deser_uint256()
        self.n = f.deser_uint32()

    def serialize(self, f):
        f.ser_uint256(self.hash)
        f.ser_uint32(self.n)

class TxIn():
    """A transaction input.

    prevout: an OutPoint object pointing at the transaction output that is being spent.
    script_sig: a script which satisfies the conditions placed in the pubkey script of the transaction output being spent.
    sequence: transaction sequence number. Used to signal whether the transaction is using opt-in RBF. Default value is 0xffffffff."""
    def __init__(self, outpoint=None, script_sig=b"", sequence=0):
        if outpoint is None:
            self.prevout = OutPoint()
        else:
            self.prevout = outpoint
        self.script_sig = script_sig
        self.sequence = sequence

    def __repr__(self):
        return "TxIn(prevout=%s script_sig=%s sequence=%i)" \
            % (repr(self.prevout), bytes_to_hex_str(self.script_sig),
               self.sequence)

    def deserialize(self, f):
        self.prevout = OutPoint()
        self.prevout.deserialize(f)
        self.script_sig = f.read(f.deser_compact_size())
        self.sequence = f.deser_uint32()

    def serialize(self, f):
        self.prevout.serialize(f)
        f.ser_string(self.script_sig)
        f.ser_uint32(self.sequence)

class TxOut():
    """A transaction output.

    value: the value of the transaction output in satoshi.
    script_pub_key: a script defining the conditions which must be satisfied to spend this output."""
    def __init__(self, value=0, script_pub_key=b""):
        self.value = value
        self.script_pub_key = script_pub_key

    def __repr__(self):
        return "TxOut(value=%i.%08i script_pub_key=%s)" \
            % (self.value // COIN, self.value % COIN,
               bytes_to_hex_str(self.script_pub_key))

    def deserialize(self, f):
        self.value = f.deser_int64()
        self.script_pub_key = f.read(f.deser_compact_size())

    def serialize(self, f):
        f.ser_int64(self.value)
        f.ser_string(self.script_pub_key)

class ScriptWitness():
    """A transaction input witness (used when spending a segwit transaction output).

    stack: a stack of data elements. Note that this is *not* encoded as a CScript. See
           https://github.com/bitcoin/bips/blob/master/bip-0141.mediawiki#witness-program for
           a full description of the witness program format."""
    def __init__(self):
        # stack is a vector of strings
        self.stack = []

    def __repr__(self):
        return "ScriptWitness(%s)" % \
               (",".join([x for x in self.stack]))

    def deserialize(self, f):
        self.stack = f.deser_string_vector()

    def serialize(self, f):
        f.ser_string_vector(self.stack)

    def is_null(self):
        if self.stack:
            return False
        return True

class TxWitness():
    """Witnesses for all of the transactions inputs. Only present in transactions which spend a segwit transaction output.

    vtxinwit: a list of witness fields, one for each transaction input in the transaction. The length of the list
              is equal to the number of transaction inputs and is set by the Transaction.deserialize() method."""
    def __init__(self):
        self.vtxinwit = []

    def __repr__(self):
        return "TxWitness(%s)" % \
               (';'.join([repr(x) for x in self.vtxinwit]))

    def deserialize(self, f):
        for i in range(len(self.vtxinwit)):
            self.vtxinwit[i].deserialize(f)

    def serialize(self, f):
        # This is different than the usual vector serialization --
        # we omit the length of the vector, which is required to be
        # the same length as the transaction's vin vector.
        for x in self.vtxinwit:
            x.serialize(f)

    def is_null(self):
        for x in self.vtxinwit:
            if not x.is_null():
                return False
        return True

class Transaction():
    """A bitcoin transaction.

    version: transaction version number: current default is 1.
    vin: a list of transaction input TxIn objects
    vout: a list of transaction output TxOut objects
    wit: the transaction witness TxWitness object
    nLockTime: a unix timestamp or block number before which this transaction is not valid
    txid: (not serialized, derived from other fields) the SHA256 digest of the transaction, excluding the witness. Serves as a unique identifier for the transaction amongst all other transactions."""
    def __init__(self, tx=None):
        if tx is None:
            self.version = 1
            self.vin = []
            self.vout = []
            self.wit = TxWitness()
            self.nLockTime = 0
        else:
            self.version = tx.version
            self.vin = copy.deepcopy(tx.vin)
            self.vout = copy.deepcopy(tx.vout)
            self.nLockTime = tx.nLockTime
            self.wit = copy.deepcopy(tx.wit)

    def __repr__(self):
        return "txid: {}, version: {}, no_txins: {}, no_txouts: {}, nLockTime: {}".format(self.txid, self.version, len(self.vin), len(self.vout), self.nLockTime)

    def deserialize(self, f):
        self.version = f.deser_int32()
        segwit = False
        if int.from_bytes(f.peep_byte(), 'big') == 0:
            if int.from_bytes(f.read(2), 'big') != 1:
                raise SerializationError("Segwit flag not set to 1")
            segwit = True
        self.vin = f.deser_vector(TxIn)
        self.vout = f.deser_vector(TxOut)
        if segwit:
            self.wit.vtxinwit = [ScriptWitness() for i in range(len(self.vin))]
            self.wit.deserialize(f)
        self.nLockTime = f.deser_uint32()

    def serialize(self, f, with_witness=True):
        flags = 0
        if not self.wit.is_null():
            flags |= 1
        f.ser_int32(self.version)
        if flags:
            dummy = []
            f.ser_vector(dummy)
            f.ser_uint8(flags)
        f.ser_vector(self.vin, 'serialize')
        f.ser_vector(self.vout, 'serialize')
        if (flags & 1) and with_witness:
            if (len(self.wit.vtxinwit) != len(self.vin)):
                # vtxinwit must have the same length as vin
                self.wit.vtxinwit = self.wit.vtxinwit[:len(self.vin)]
                for i in range(len(self.wit.vtxinwit), len(self.vin)):
                    self.wit.vtxinwit.append(ScriptWitness())
            self.wit.serialize(f)
        f.ser_uint32(self.nLockTime)

    @property
    def txid(self):
        f = BCBytesStream()
        self.serialize(f, False)
        return encode(hash256(f.getvalue())[::-1], 'hex_codec').decode('ascii')

class MerkleTransaction(Transaction):
    """A transaction along with an index to its location in the blockchain. Subclasses Transaction class.

    Despite its name, this object does not store a Merkle proof. Older versions stored the Merkle proof, but
    it wasn't used for anything other than an expensive sanity check. The merkle_branch field was removed in
    a backwards-compatible way in https://github.com/bitcoin/bitcoin/pull/6550.

    hash_block: the hash of the block that includes this transaction.
    merkle_branch: previously used to store the Merkle proof for the transaction's inclusion in the block. For new wallets, this should be 0x00 for backwards compatibility.
    index: the index of the transaction within the block."""
    def __init__(self):
        super().__init__()
        self.hash_block = 0
        self.merkle_branch = 0
        self.index = 0

    def deserialize(self, f):
        super().deserialize(f)
        self.hash_block = f.read(32)
        # For new wallets, merkle_branch should be zero
        merkle_proof_len = f.deser_compact_size()
        self.merkle_branch = f.read(32 * merkle_proof_len)
        self.index = f.deser_int32()

class WalletTransaction(MerkleTransaction):
    """A Transaction together with meta-data for use by the wallet. Subclasses MerkleTransaction class.

    vtxPrev: unused - should be 0x00 for backwards compatibility. Previously used to store the wallet transaction's ancestors. Removed in https://github.com/bitcoin/bitcoin/pull/3694.
    mapValue: transaction metadata. Can contain the following keys:
        - comment: a user-set comment string, provided when using the sendtoaddress RPC.
        - to: a user-set 'to' comment string, provided when using the sendtoaddress RPC.
        - replaces_txid: txid (as HexStr) of transaction replaced by this transaction using bumpfee.
        - replaced_by_txid: txid (as HexStr) of transaction that replaced this transaction using bumpfee.
        - fromaccount: the account that this transaction was sent from. Set when using the sendfrom RPC. Note that accounts and sendfrom are both deprecated.
        - n: the wallet transaction's index in the wallet's ordered list of transactions.
        - timesmart: stable timestamp that never changes, and reflects the order a transaction was added to the wallet. See https://github.com/bitcoin/bitcoin/pull/1393.
        'from', 'message' and 'spent' are obsolete keys that can be ignored.
    order_form: a list of key-value pairs related to a payment
        - PaymentRequest: a serialized payment request (see https://github.com/bitcoin/bitcoin/pull/2539 for details).
        - Message: the message part of a bitcoin: URI, for example bitcoin:123...?message=example.
    time_received_is_tx_time: unused int. This position in the serialized transaction was briefly used as a version field. See
        https://github.com/bitcoin/bitcoin/commit/e4ff4e6898d378b1a3e83791034a7af455fde3ab#diff-23cfe05393c8433e384d2c385f06ab93R776 for example.
    time_received: the clock time when the transaction was received by the wallet.
    from_me: whether the transaction was created by this wallet software. Set to 1 if it was created by this wallet or 0 if it was created externally and received over the network or sent using
        the sendrawtransaction RPC.
    spent: unused. Previously used to mark whether the transaction had been spent. Removed in https://github.com/bitcoin/bitcoin/pull/3694."""
    def __init__(self):
        super().__init__()
        self.vtxPrev = []
        self.mapValue = {}
        self.order_form = []
        self.time_received_is_tx_time = 0
        self.time_received = 0
        self.from_me = False
        self.spent = False

    def deserialize(self, f):
        super().deserialize(f)
        n_vtx_prev = f.deser_compact_size()  # Should be zero!
        for i in range(n_vtx_prev):
            self.vtxPrev.append(f.parse_merkle_tx())

        n_map_value = f.deser_compact_size()
        for i in range(n_map_value):
            key = f.deser_string()
            value = f.deser_string()
            self.mapValue[key] = value
        n_order_form = f.deser_compact_size()
        for i in range(n_order_form):
            first = f.deser_string()
            second = f.deser_string()
            self.order_form.append((first, second))
        self.time_received_is_tx_time = f.deser_uint32()
        self.time_received = f.deser_uint32()
        self.from_me = f.deser_boolean()
        self.spent = f.deser_boolean()

class BlockLocator():
    """Describes a place in the block chain.

    version: TODO
    have: TODO."""
    def __init__(self):
        self.version = 0
        self.have = []

    def deserialize(self, f):
        self.version = f.deser_uint32()
        for block in range(f.deser_compact_size()):
            self.have.append(f.read(32).hex())

    def __repr__(self):
        if self.have:
            best_block = self.have[0]
        else:
            best_block = "empty"
        return "version:{}, block hash: {}\n".format(self.version, best_block)

class KeyPool():
    """A Keypool Entry.
    
    version: TODO
    time: TODO
    pub_key: TODO."""
    def __init__(self):
        self.version = 0
        self.time = 0
        self.pub_key = b''

    def deserialize(self, f):
        self.version = f.deser_uint32()
        self.time = f.deser_int64()
        self.pub_key = f.read(f.deser_compact_size()).hex()

    def __repr__(self):
        return "version: {}, time: {}, pub_key: 0x{}".format(self.version, time.ctime(self.time), self.pub_key)

class Account():
    """A wallet account.

    version: TODO
    pub_key: TODO."""
    def __init__(self):
        self.version = 0
        self.pub_key = b''

    def deserialize(self, f):
        self.version = f.deser_int32()
        self.pub_key = f.read(f.deser_compact_size()).hex()

    def __repr__(self):
        return "version: {}, pub_key: 0x{}".format(self.version, self.pub_key)

class HDChain():
    """A wallet HD chain.
    
    version: TODO
    external_chain_counter: TODO
    master_key_id: TODO
    internal_chain_counter: TODO."""
    def __init__(self):
        self.version = 0
        self.external_chain_counter = 0
        self.master_key_id = b''
        self.internal_chain_counter = 0

    def deserialize(self, f):
        self.version = f.deser_uint32()
        self.external_chain_counter = f.deser_uint32()
        self.master_key_id = f.read(20).hex()
        if self.version > VERSION_HD_CHAIN_SPLIT:
            self.internal_chain_counter = f.deser_uint32()

    def __repr__(self):
        return "version: {}, master_key_id: {}, external_chain_counter: {}, internal_chain_counter: {}".format(self.version, self.master_key_id, self.external_chain_counter, self.internal_chain_counter)

class AccountingEntry():
    """Accounting entry for internal wallet transfers.
    
    account: TODO
    index: TODO
    version: TODO
    credit_debit: TODO
    time: TODO
    other_account: TODO
    comment: TODO."""
    def __init__(self):
        self.account = ''
        self.index = 0
        self.version = 0
        self.credit_debit = 0
        self.time = 0
        self.other_account = ''
        self.comment = ''

    def deserialize(self, f):
        self.version = f.read_int32()
        self.credit_debit = f.read_int64()
        self.time = f.read_int64()
        self.other_account = f.deser_string()
        self.comment = f.deser_string()

    def __repr__(self):
        return "version: {}, from_account: {}, index: {}, to_account: {}, credit_debit: {}, time: {}, comment: {}".format(self.version, self.index, self.account, self.other_account, self.credit_debit, time.ctime(self.time), self.comment)

class KeyMeta():
    """Metadata for a wallet key.

    version: the version of the KeyMeta object. Can be one of the following values:
        - 1 (VERSION_BASIC)
        - 10 (VERSION_WITH_HDDATA): as VERSION_BASIC, but the metadata also contains the HD key info.
    create_time: when the key was created.
    hd_key_path: (only present if version is >= VERSION_WITH_HDDATA): the BIP 32 HD key derivation path.
    hd_master_key_id: (only present if version is >= VERSION_WITH_HDDATA): the id of the HD masterkey used to derive this key."""
    def __init__(self):
        self.version = 0
        self.create_time = 0
        self.hd_key_path = 'Not HD'
        self.hd_master_key_id = 'Not HD'

    def deserialize(self, f):
        self.version = f.deser_int32()
        self.create_time = f.deser_int64()
        if self.version >= VERSION_WITH_HDDATA:
            self.hd_key_path = f.deser_string()
            self.hd_master_key_id = f.read(20).hex()

    def __repr__(self):
        return "version: {}, create_time: {}, hd_key_path: {}, hd_master_key_id: {}".format(self.version, time.ctime(self.create_time), self.hd_key_path, self.hd_master_key_id)

class Address():
    """Information about a remote bitcoin node, used by bitcoind's addrman.

    version: version of the bitcoind software used to serialize this Address object to disk.
    time: last time the Address object was updated.
    services: A bitfield of node services:
        - NODE_NETWORK (1 << 0): the node is capable of serving the complete block chain.
        - NODE_GETUTXO (1 << 1): the node is capable of responding to the getutxo protocol request. See BIP 64.
        - NODE_BLOOM (1 << 2): the node is capable and willing to handle bloom-filtered connections.
        - NODE_WITNESS (1 << 3): the node can be asked for blocks and transactions including witness data.
        - NODE_NETWORK_LIMITED (1 << 10): the same as NODE_NETWORK with the limitation of only serving the last 288 (2 day) blocks.
                                          See BIP159 for details.
    ip: a 16 byte array representing the ip address of the remote node. An IPv4 address is represented by
        10 bytes of 0x00, 2 bytes of 0xff, and 4 bytes of the IP address.
    ipv4: (not serialized) an internal boolean to mark whether this is an ipv4 address.
    port: the port number of the remote node."""
    def __init__(self):
        self.version = 0
        self.time = 0
        self.services = 0
        self.ip = b''
        self.port = 0

    def __repr__(self):
        if self.ipv4:
            ret = ".".join([str(int.from_bytes(self.ip[n:n + 1], 'big')) for n in range(12, 16)])
        else:
            ret = ":".join([self.ip[n:n + 1].hex() for n in range(16)])

        ret += ", port: {}".format(self.port)

        return ret

    def deserialize(self, f):
        self.version = f.deser_uint32()
        self.time = f.deser_uint32()
        self.services = f.deser_uint64()
        self.ip = f.read(16)
        self.port = f.deser_uint16(big=True)

        if int.from_bytes(self.ip[0:12], 'big') == 0xffff:
            self.ipv4 = True
        else:
            self.ipv4 = False

class AddrInfo(Address):
    """Extended information about a remote bitcoin node. Subclasses Address.

    source: where we first learned about this address.
    last_success: last successful connection by us.
    attempts: connection attempts since last successful attempt."""
    def __init__(self):
        super().__init__()
        self.source = b''
        self.last_success = 0
        self.attempts = 0

    def __repr__(self):
        return super().__repr__()

    def deserialize(self, f):
        super().deserialize(f)
        self.source = f.read(16)
        self.last_success = f.deser_int64()
        self.attempts = f.deser_int32()

class Subnet():
    """An IPv4 or IPv6 subnet.

    network: a 16 byte array representing the host or subnet. An IPv4 address is represented by
             10 bytes of 0x00, 2 bytes of 0xff, and 4 bytes of the IP address.
    netmask: the netmask for the subnet."""
    def __init__(self):
        self.network = b''
        self.netmask = b''

    def __repr__(self):
        if self.ipv4:
            ret = ".".join([str(int.from_bytes(self.network[n:n + 1], 'big')) for n in range(12, 16)])
            ret += ", netmask: "
            ret += ".".join([str(int.from_bytes(self.netmask[n:n + 1], 'big')) for n in range(12, 16)])
        else:
            ret = ":".join([self.network[n:n + 1].hex() for n in range(16)])
            ret += ", netmask: "
            ret += ":".join([self.netmask[n:n + 1].hex() for n in range(16)])

        return ret

    def deserialize(self, f):
        self.network = f.read(16)
        self.netmask = f.read(16)
        self.valid = f.deser_boolean()

        if int.from_bytes(self.network[0:12], 'big') == 0xffff:
            self.ipv4 = True
        else:
            self.ipv4 = False

class BanEntry():
    """Information about a banned subnet or host.

    version: the version of bitcoind which serialized this BanEntry.
    create_time: when the ban started.
    ban_until: when the ban expires.
    reason: the reason for the ban. Can be one of:
        - unknown: reason for ban is not known. reason should never be set to this value.
        - manually_added: the ban was manually added using the setban RPC.
        - node_misbehaving: the node was banned automatically because it violated DOS behaviour rules."""
    def __init__(self):
        self.version = 0
        self.create_time = 0
        self.ban_until = 0
        self.reason = BanReason.UNKNOWN

    def __repr__(self):
        ret = "version: {}, create_time: {}, ban_until: {}".format(
            self.version,
            time.ctime(self.create_time),
            time.ctime(self.ban_until),
        )
        ret += ", reason: "
        if self.reason == BanReason.UNKNOWN:
            ret += "unknown"
        elif self.reason == BanReason.MANUALLY_ADDED:
            ret += "manually_added"
        elif self.reason == BanReason.NODE_MISBEHAVING:
            ret += "node_misbehaving"

        return ret

    def deserialize(self, f):
        self.version = f.deser_int32()
        self.create_time = f.deser_int64()
        self.ban_until = f.deser_int64()
        self.reason = BanReason(f.deser_int8())

class Ban():
    """A single entry in the banmap.

    subnet: a SubNet object
    ban_entry: a BanEntry object"""
    def __init__(self):
        self.subnet = None
        self.ban_entry = None

    def deserialize(self, f):
        self.subnet = Subnet()
        self.subnet.deserialize(f)
        self.ban_entry = BanEntry()
        self.ban_entry.deserialize(f)
