from typing import List, Dict, Any, Tuple

from ethereum_types.bytes import Bytes20, Bytes0
from ethereum_types.numeric import U256, Uint

from ethereum.exceptions import InvalidBlock
from ethereum.frontier.blocks import Block
from ethereum.frontier.fork import execution_transaction, ApplyBodyOutput
from ethereum.frontier.transactions import Transaction, signing_hash
from ethereum.utils import temp_param
from ethereum.utils.hexadecimal import hex_to_bytes


class MinerNode:
    _instance = None
    def __new__(cls, chain):
        if cls._instance is None:
            cls._instance = super(MinerNode, cls).__new__(cls)
            cls._instance.chain = chain
            cls._instance.transaction_pool = []
        return cls._instance

    def json_transaction(self,data: Dict[str, Any]):
        """
        Create a transaction object from the JSON-RPC data.
        """
        params = data['params'][0]
        # print("tx nonce:",U256(int(params['nonce'], 16)))
        if 'to' in params and params['to'] != "0x0000000000000000000000000000000000000000":
            to = Bytes20(hex_to_bytes(params['to']))
        else:
            to = Bytes0(b"")

        if "gasPrice" in params:
            gas_price=Uint(int(params['gasPrice'], 16))
        elif "maxFeePerGas" in params:
            gas_price=Uint(int(params['maxFeePerGas'], 16))
        else:
            gas_price=Uint(20*1e9)

        tx = Transaction(
            nonce=U256(int(params['nonce'], 16)),
            gas_price=gas_price,
            gas=Uint(int(params['gas'], 16)),
            to=to,
            value=U256(int(params['value'], 16)),
            data=hex_to_bytes(params['data']),
            v=temp_param.TRANSACTION_v,
            r=temp_param.TRANSACTION_r,
            s=temp_param.TRANSACTION_s
        )

        tx_hash = signing_hash(tx)
        return tx,tx_hash
    def add_transaction(self, tx: Transaction):
        # Add transaction validation logic
        if self.validate_transaction(tx):
            self.transaction_pool.append(tx)
            print(f"Transaction added to pool: {tx}")
        else:
            print(f"Invalid transaction: {tx}")

    def validate_transaction(self, transaction: Transaction) -> bool:
        # Verify transactions to check if the signature of the transaction is valid.
        # Confirm that there is sufficient balance in the sender's account to pay the transfer amount and Gas fee.
        # Verify that the format and content of the transaction are correct.
        return True

    def mine_block(self):
        if not self.transaction_pool:
            print("No transactions to mine.")
            return

        # Select transactions (here simply select all transactions)
        txs: Tuple[Transaction, ...] = tuple(self.transaction_pool)
        self.transaction_pool.clear()

        # Execute transactions packaged as blocks
        new_block=execution_transaction(txs, self.chain)

        # The consensus mechanism verifies and adds blocks to the blockchain, local testing does not need to verify blocks
        # validate_block()

        #add block to blockchain
        self.chain.blocks.append(new_block)
        if len(self.chain.blocks) > 255:
            self.chain.blocks = self.chain.blocks[-255:]

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
