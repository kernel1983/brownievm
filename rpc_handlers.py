import web3

from loguru import logger
import setting
import ethereum_types.numeric
import ethereum.crypto.hash
import ethereum.genesis
import ethereum.frontier.fork
import ethereum.frontier.trie
import ethereum.frontier.state
import ethereum.frontier.transactions
from ethereum.frontier.trie import trie_get
from ethereum.frontier.blocks import hash_block
from ethereum.mine import MinerNode

method_mapping = {}


def rpc_method(method_name):
    def decorator(func):
        method_mapping[method_name] = func
        return func

    return decorator


description = ethereum.genesis.GenesisFork(
    Address=ethereum.frontier.fork_types.Address,
    Account=ethereum.frontier.fork_types.Account,
    Trie=ethereum.frontier.trie.Trie,
    Bloom=ethereum.frontier.fork_types.Bloom,
    Header=ethereum.frontier.blocks.Header,
    Block=ethereum.frontier.blocks.Block,
    set_account=ethereum.frontier.state.set_account,
    set_storage=ethereum.frontier.state.set_storage,
    state_root=ethereum.frontier.state.state_root,
    root=ethereum.frontier.trie.root,
    hex_to_address=ethereum.frontier.utils.hexadecimal.hex_to_address,
)

TESTNET_GENESIS_CONFIGURATION = ethereum.genesis.get_genesis_configuration("testnet.json")

state = ethereum.frontier.state.State()
chain = ethereum.frontier.fork.BlockChain([], state, ethereum_types.numeric.U64(31337))
ethereum.genesis.add_genesis_block(description, chain, TESTNET_GENESIS_CONFIGURATION)
miner = MinerNode(chain)


@rpc_method('eth_blockNumber')
def handle_eth_blockNumber(req, rpc_id):
    latest_block_height = chain.blocks[-1].header.number
    return {'jsonrpc': '2.0','result': hex(latest_block_height), 'id': rpc_id}


@rpc_method('eth_getBlockByNumber')
def handle_eth_getBlockByNumber(req, rpc_id):
    latest_block_height = chain.blocks[-1].header.number
    header = chain.blocks[-1].header
    latest_block_hashes = hash_block(header)

    if not latest_block_hashes:
        latest_block_hashes.append('0' * 64)
    return {
        "jsonrpc": "2.0",
        "id": rpc_id,
        "result": {
            "number": hex(latest_block_height),
            "hash": '0x' + latest_block_hashes.hex(),
            "parentHash": '0x' + header.parent_hash.hex(),
            "nonce": '0x' + header.nonce.hex(),
            "logsBloom": '0x' + header.bloom.hex(),
            "transactionsRoot": '0x' + header.transactions_root.hex(),
            "stateRoot": '0x' + header.state_root.hex(),
            "receiptsRoot": '0x' + header.receipt_root.hex(),
            "miner": "0xc014ba5ec014ba5ec014ba5ec014ba5ec014ba5e",
            "difficulty": hex(header.difficulty),
            "totalDifficulty": "0x20001",
            "extraData": "0x",
            "size": "0xe5f",
            "gasLimit": hex(header.gas_limit),
            "gasUsed": hex(header.gas_used),
            "baseFeePerGas": "0x0",
            "timestamp": "0x644b949c",
            "transactions": [],
            "uncles": []
        }
    }


@rpc_method('eth_getBalance')
def handle_eth_getBalance(req, rpc_id):
    address = web3.Web3.to_checksum_address(req['params'][0])
    account = state._main_trie._data[web3.Web3.to_bytes(hexstr=address)]
    balance = int(account.balance)
    return {'jsonrpc': '2.0','result': hex(balance), 'id': rpc_id}

@rpc_method('eth_getTransactionReceipt')
def handle_eth_getTransactionReceipt(req, rpc_id):
    pass

@rpc_method('eth_getCode')
def handle_eth_getCode(req, rpc_id):
    resp = {'jsonrpc': '2.0', 'result': '0x5208', 'id': rpc_id}  # 21000 gas
    return resp

@rpc_method('eth_gasPrice')
def handle_eth_gasPrice(req, rpc_id):
    resp = {'jsonrpc': '2.0', 'result': '0x0', 'id': rpc_id}
    return resp

@rpc_method('eth_estimateGas')
def handle_eth_estimateGas(req, rpc_id):
    resp = {'jsonrpc': '2.0', 'result': '0x0', 'id': rpc_id}
    return resp

@rpc_method('eth_maxPriorityFeePerGas')
def handle_maxPriorityFeePerGas(req, rpc_id):
    resp = {'jsonrpc': '2.0', 'result': '0x0', 'id': rpc_id}
    return resp

@rpc_method('eth_getTransactionCount')
def handle_eth_getTransactionCount(req, rpc_id):
    address = req['params'][0].lower()
    account = state._main_trie._data[web3.Web3.to_bytes(hexstr=address)]

    nonce = account.nonce

    resp = {'jsonrpc': '2.0', 'result': hex(nonce), 'id': rpc_id}
    return resp

@rpc_method('eth_getBlockByHash')
def handle_eth_getBlockByHash(req, rpc_id):
    resp = {'jsonrpc': '2.0', 'result': '0x0', 'id': rpc_id}
    return resp


@rpc_method('eth_sendTransaction')
def handle_eth_sendTransaction(req, rpc_id):
    tx, tx_hash = miner.json_transaction(req)
    miner.add_transaction(tx)
    miner.mine_block()
    resp = {'jsonrpc': '2.0', 'result': '0x' + tx_hash.hex(), 'id': rpc_id}
    return resp


@rpc_method('eth_getTransactionByHash')
def handle_eth_getTransactionByHash(req, rpc_id):
    tx_hash = req["params"][0][2:]
    tx_bytes = bytes.fromhex(tx_hash)
    receipt = trie_get(chain.state._receipt_trie, tx_bytes)
    transaction = trie_get(chain.state._transaction_trie, tx_bytes)
    block_number = receipt.block_number
    to_address = '0x' + transaction.to.hex() if transaction.to.hex() else None

    resp = {'jsonrpc': '2.0', 'result': {
        "blockHash": '0x' + hash_block(chain.blocks[block_number].header).hex(),
        "blockNumber": hex(block_number),
        "chainId": int(chain.chain_id),
        "from": '0x' + receipt.from_addr.hex(),
        "gas": hex(receipt.gas_used),
        "gasPrice": hex(receipt.gas_price),
        "hash": '0x' + receipt.transaction_hash.hex(),
        "input": "0x",
        "nonce": hex(transaction.nonce),
        "to": to_address,
        "transactionIndex": hex(receipt.transaction_index),
        "value": hex(transaction.value),
        # "v": hex(transaction.v),
        # "r": hex(transaction.r),
        # "s": hex(transaction.s),
    }, 'id': rpc_id}
    return resp

@rpc_method('eth_call')
def handle_eth_call(req, rpc_id):
    params = req.get('params', [])

    # try:
    # if len(params) > 0:
    # if 'to' in params[0] and 'data' in params[0] and params[0]['to'].lower() in contracts.contract_map:
    # contract = contract_map[params[0]['to'].lower()]
    tx_to = params[0]['to']
    tx_data = params[0]['data'].replace('0x', '')
    contract_account = state._main_trie._data[web3.Web3.to_bytes(hexstr=tx_to)]
    result = contract_account.code
    resp = {'jsonrpc': '2.0', 'result': '0x' + result.hex(), 'id': rpc_id}
    return resp

@rpc_method('eth_sendRawTransaction')
def handle_eth_sendRawTransaction(req, rpc_id):

    resp = {'jsonrpc': '2.0', 'result': '0x', 'id': rpc_id}
    return resp


@rpc_method('eth_feeHistory')
def handle_eth_feeHistory(req, rpc_id):
    resp = {'jsonrpc': '2.0', 'result': {}, 'id': rpc_id}
    return resp

@rpc_method('web3_clientVersion')
def handle_web3_clientVersion(req, rpc_id):
    resp = {'jsonrpc': '2.0', 'result': 'BitPoW', 'id': rpc_id}
    return resp


@rpc_method('eth_chainId')
def handle_eth_chainId(req, rpc_id):
    resp = {'jsonrpc': '2.0', 'result': hex(setting.CHAIN_ID), 'id': rpc_id}
    return resp


@rpc_method('net_version')
def handle_net_version(req, rpc_id):
    resp = {'jsonrpc': '2.0', 'result': str(setting.CHAIN_ID), 'id': rpc_id}
    return resp


@rpc_method('evm_snapshot')
def handle_evm_snapshot(req, rpc_id):
    resp = {'jsonrpc': '2.0', 'result': str(setting.CHAIN_ID), 'id': rpc_id}
    return resp


@rpc_method('eth_accounts')
def handle_eth_accounts(req, rpc_id):
    resp = {'jsonrpc': '2.0', 'result': [
        '0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266',
        '0x70997970C51812dc3A010C7d01b50e0d17dc79C8',
        '0x3C44CdDdB6a900fa2b585dd299e03d12FA4293BC',
        '0x90F79bf6EB2c4f870365E785982E1f101E93b906',
        '0x15d34AAf54267DB7D7c367839AAf71A00a2C6A65',
        '0x9965507D1a55bcC2695C58ba16FB37d819B0A4dc',
        '0x976EA74026E726554dB657fA54763abd0C3a0aa9',
        '0x14dC79964da2C08b23698B3D3cc7Ca32193d9955',
        '0x23618e81E3f5cdF7f54C3d65f7FBc0aBf5B21E8f',
        '0xa0Ee7A142d267C1f36714E4a8F75612F20a79720'
    ], 'id': rpc_id}
    return resp
