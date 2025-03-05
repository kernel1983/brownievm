"""
A `Block` is a single link in the chain that is Ethereum. Each `Block` contains
a `Header` and zero or more transactions. Each `Header` contains associated
metadata like the block number, parent block hash, and how much gas was
consumed by its transactions.

Together, these blocks form a cryptographically secure journal recording the
history of all state transitions that have happened since the genesis of the
chain.
"""
from dataclasses import dataclass
from typing import Tuple, Optional

from ethereum_rlp import rlp
from ethereum_types.bytes import Bytes, Bytes8, Bytes32, Bytes256, Bytes20, Bytes0
from ethereum_types.frozen import slotted_freezable
from ethereum_types.numeric import U256, Uint

from ..crypto.hash import Hash32, keccak256
from .fork_types import Address, Bloom, Root
from .transactions import Transaction


@slotted_freezable
@dataclass
class Header:
    """
    Header portion of a block on the chain.
    """

    parent_hash: Hash32
    ommers_hash: Hash32
    coinbase: Address
    state_root: Root
    transactions_root: Root
    receipt_root: Root
    bloom: Bloom
    difficulty: Uint
    number: Uint
    gas_limit: Uint
    gas_used: Uint
    timestamp: U256
    extra_data: Bytes
    mix_digest: Bytes32
    nonce: Bytes8


@slotted_freezable
@dataclass
class Block:
    """
    A complete block.
    """

    header: Header
    transactions: Tuple[Transaction, ...]
    ommers: Tuple[Header, ...]


@slotted_freezable
@dataclass
class Log:
    """
    Data record produced during the execution of a transaction.
    """

    address: Address
    topics: Tuple[Hash32, ...]
    data: bytes


# @slotted_freezable
@dataclass
class Receipt:
    """
    Result of a transaction.
    """

    post_state: Root=Bytes32(b"0" * 32)
    cumulative_gas_used: Uint=Uint(0)
    bloom: Bloom=Bytes0(b"")
    logs: Tuple[Log, ...]=()
    from_addr: Optional[Address]=Bytes0(b"")
    to: Optional[Address]=Bytes0(b"")
    transaction_index: Uint=Uint(0)
    block_number: Uint=Uint(0)
    transaction_hash: Hash32=Bytes0(b"")
    status: bool=True # 交易状态，通常为 True 表示成功，False 表示失败
    gas_used: Uint=Uint(0)
    gas_price: Uint=Uint(0)
    # 合约地址，如果交易创建了新合约，则为该合约的地址；否则为 None
    contract_address: Optional[Address]=Bytes0(b"")



def hash_block(header: Header) -> Hash32:
    """
    Compute the hash of a block header used in the signature.
    ----------
    tx :
        Transaction of interest.

    Returns
    -------
    hash : `ethereum.crypto.hash.Hash32`
        Hash of the block.header.
    """
    return keccak256(
        rlp.encode(
            (
            header.nonce,
            header.parent_hash,
            header.ommers_hash,
            header.coinbase,
            header.state_root,
            header.transactions_root,
            header.receipt_root,
            header.bloom,
            header.difficulty,
            header.number,
            header.gas_limit,
            header.gas_used,
            header.timestamp,
            header.extra_data,
            header.mix_digest,
            header.nonce,
            )
        )
    )
