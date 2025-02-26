import json
import time
import logging
from typing import Optional, Tuple, Dict, Any

from ethereum.utils import temp_param
from ethereum_rlp import rlp
from ethereum_types.bytes import Bytes20, Bytes, Bytes32, Bytes8, Bytes256
from ethereum_types.numeric import U256, Uint

from ethereum.crypto.hash import Hash32, keccak256
from ethereum.exceptions import InvalidTransaction, InvalidBlock
from ethereum.frontier import vm
from ethereum.frontier.blocks import Receipt, Log, Block, Header
from ethereum.frontier.bloom import logs_bloom
from ethereum.frontier.fork import process_transaction, BlockChain, get_last_256_block_hashes, make_receipt, pay_rewards, ApplyBodyOutput
from ethereum.frontier.state import State, state_root
from ethereum.frontier.transactions import Transaction, validate_transaction, signing_hash
from ethereum.frontier.trie import Trie, trie_set, root, trie_get
from ethereum.utils.hexadecimal import hex_to_bytes

# logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


def create_transaction(data: Dict[str, Any]) -> Transaction:
    """
    Create a transaction object from the JSON-RPC data.
    """
    params = data['params'][0]
    return Transaction(
        nonce=U256(int(params['nonce'], 16)),
        gas_price=Uint(int(params['maxFeePerGas'], 16)),
        gas=Uint(int(params['gas'], 16)),
        to=Bytes20(hex_to_bytes(params['to'])),
        value=U256(int(params['value'], 16)),
        data=params['data'],
        v=temp_param.TRANSACTION_v,
        r=temp_param.TRANSACTION_r,
        s=temp_param.TRANSACTION_s
    )


def process_transaction_and_create_receipt(
    tx: Transaction,
    sender_address: Bytes20,
    chain: BlockChain
) -> Tuple[Uint, Tuple[Log, ...], Receipt]:
    """
    Handle transactions and generate receipts.
    """
    block = chain.blocks[-1]
    block_gas_limit=temp_param.BLOCK_gas_limit

    env = vm.Environment(
        caller=sender_address,
        origin=sender_address,
        block_hashes=get_last_256_block_hashes(chain),
        coinbase=temp_param.COINBASE_address,
        number=block.header.number,
        gas_limit=block_gas_limit,
        gas_price=temp_param.ENVIRONMENT_gas_price,
        time=block.header.timestamp,
        difficulty=block.header.difficulty,
        state=chain.state,
        traces=[]
    )

    gas_used, logs = process_transaction(env, tx)
    receipt = make_receipt(tx, state_root(chain.state), (block_gas_limit - gas_used), logs)
    return gas_used, logs, receipt


def create_new_block(
    chain: BlockChain,
    transactions: Tuple[Transaction, ...],
    tx_root: Bytes32,
    receipt_root: Bytes32,
    block_logs_bloom: Bytes256,
    block_gas_used: Uint,
    coinbase: Bytes20
) -> Block:
    """
    Create new Block。
    """
    previous_nonce = chain.blocks[-1].header.nonce
    new_nonce_int = int.from_bytes(previous_nonce, byteorder='big') + 1

    header = Header(
        parent_hash=keccak256(rlp.encode(chain.blocks[-1].header.parent_hash)),
        ommers_hash=keccak256(coinbase),
        coinbase=coinbase,
        state_root=state_root(chain.state),
        transactions_root=tx_root,
        receipt_root=receipt_root,
        bloom=block_logs_bloom,
        difficulty=temp_param.HEADER_difficulty,
        number=Uint(int(chain.blocks[-1].header.number) + 1),
        gas_limit=temp_param.HEADER_gas_limit,
        gas_used=block_gas_used,
        timestamp=U256(int(time.time())),
        extra_data=temp_param.HEADER_extra_data,
        mix_digest=keccak256(coinbase),
        nonce=Bytes8(new_nonce_int.to_bytes(8, byteorder='big'))
    )

    ommers: Tuple[Header, ...] = (header,)
    return Block(header=header, transactions=transactions, ommers=ommers)


def execution(data: Dict, chain: BlockChain) -> Tuple[ApplyBodyOutput, bytes, Block]:
    """
    Execution transactions, and generate new blocks.
    """
    tx_trie = Trie(secured=False, default=None)
    receipt_trie = Trie(secured=False, default=None)
    block_logs: Tuple[Log, ...] = ()
    sender_address = Bytes20(hex_to_bytes(data['params'][0]['from']))


    tx = create_transaction(data)

    tx_hash = signing_hash(tx)
    trie_set(tx_trie, tx_hash, tx)

    gas_used, logs, receipt = process_transaction_and_create_receipt(tx, sender_address, chain)
    trie_set(receipt_trie, tx_hash, receipt)
    block_logs += logs

    coinbase=temp_param.COINBASE_address
    block_gas_limit=temp_param.BLOCK_gas_limit

    pay_rewards(chain.state, chain.blocks[-1].header.number,coinbase, chain.blocks[-1].ommers)

    block_gas_used = block_gas_limit - gas_used
    block_logs_bloom = logs_bloom(block_logs)

    transactions: Tuple[Transaction, ...] = (tx,)
    tx_root = root(tx_trie)
    receipt_root = root(receipt_trie)

    new_block = create_new_block(chain, transactions, tx_root, receipt_root, block_logs_bloom, block_gas_used, coinbase)

    return ApplyBodyOutput(
        block_gas_used,
        tx_root,
        receipt_root,
        block_logs_bloom,
        state_root(chain.state),
    ), tx_hash, new_block


def validate_block(apply_body_output: ApplyBodyOutput, new_block: Block) -> None:
    """
    Verify the legitimacy of the block.
    """
    if apply_body_output.block_gas_used != new_block.header.gas_used:
        raise InvalidBlock(f"Gas used mismatch: {apply_body_output.block_gas_used} != {new_block.header.gas_used}")
    if apply_body_output.transactions_root != new_block.header.transactions_root:
        raise InvalidBlock("Transactions root mismatch")
    if apply_body_output.state_root != new_block.header.state_root:
        raise InvalidBlock("State root mismatch")
    if apply_body_output.receipt_root != new_block.header.receipt_root:
        raise InvalidBlock("Receipt root mismatch")
    if apply_body_output.block_logs_bloom != new_block.header.bloom:
        raise InvalidBlock("Logs bloom mismatch")


def eth_sendTransaction(data: Dict, chain: BlockChain) -> bytes:
    """
    Handle the request for sending transactions。
    """
    apply_body_output, tx_hash, new_block = execution(data, chain)
    validate_block(apply_body_output, new_block)

    chain.blocks.append(new_block)
    if len(chain.blocks) > 255:
        chain.blocks = chain.blocks[-255:]

    logger.info(f"New block added with hash: {tx_hash.hex()}")
    return tx_hash


def eth_getTransactionByHash(tx_hash: Hash32) -> Optional[Transaction]:
    """
    Obtain the transaction content based on the transaction hash.
    """
    # TODO: Implement specific logic
    pass