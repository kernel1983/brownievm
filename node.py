
import json
import hashlib
import time
import types

import tornado
# import requests

import web3
import eth_account
# import eth_typing
import eth_abi
import hexbytes
from loguru import logger

# import chain
# import database
# import tree
# import vm

# import contracts
# import state
# import eth_tx
# import console
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

description: ethereum.genesis.GenesisFork[
    ethereum.frontier.fork_types.Address,
    ethereum.frontier.fork_types.Account,
    ethereum.frontier.state.State,
    ethereum.frontier.trie.Trie,
    ethereum.frontier.fork_types.Bloom,
    ethereum.frontier.blocks.Header,
    ethereum.frontier.blocks.Block
] = ethereum.genesis.GenesisFork(
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

class EthRpcHandler(tornado.web.RequestHandler):
    # def options(self):
    #     self.add_header('access-control-allow-methods', 'OPTIONS, POST')
    #     self.add_header('access-control-allow-origin', '*')
    #     self.add_header('access-control-allow-headers', 'content-type')
    #     self.add_header('accept', 'application/json')

    # def get(self):
    #     self.redirect('/dashboard')

    def post(self):
        # print(self.request.arguments)
        # self.add_header('access-control-allow-methods', 'OPTIONS, POST')
        # self.add_header('access-control-allow-origin', '*')
        req = tornado.escape.json_decode(self.request.body)
        logger.info(req)
        rpc_id = req.get('id', '0')
        if req.get('method') == 'eth_blockNumber':
            latest_block_height = chain.blocks[-1].header.number
            print(latest_block_height)
            resp = {'jsonrpc':'2.0', 'result': hex(latest_block_height), 'id':rpc_id}

        elif req.get('method') == 'eth_getBlockByNumber':
            latest_block_height = chain.blocks[-1].header.number
            header=chain.blocks[-1].header
            latest_block_hashes = hash_block(header)

            if not latest_block_hashes:
                latest_block_hashes.append('0'*64)
            resp = {"jsonrpc":"2.0", "id": rpc_id,
                "result":{
                    "number": hex(latest_block_height),
                    "hash": '0x'+latest_block_hashes.hex(),
                    "parentHash":'0x'+header.parent_hash.hex(),
                    "nonce":'0x'+header.nonce.hex(),
                    # "mixHash":"0x0000000000000000000000000000000000000000000000000000000000000000",
                    # "sha3Uncles":"0x1dcc4de8dec75d7aab85b567b6ccd41ad312451b948a7413f0a142fd40d49347",
                    "logsBloom":'0x'+header.bloom.hex(),
                    "transactionsRoot":'0x'+header.transactions_root.hex(),
                    "stateRoot":'0x'+header.state_root.hex(),
                    "receiptsRoot":'0x'+header.receipt_root.hex(),
                    "miner":"0xc014ba5ec014ba5ec014ba5ec014ba5ec014ba5e",
                    "difficulty":hex(header.difficulty),
                    "totalDifficulty":"0x20001",
                    "extraData":"0x",
                    "size":"0xe5f",
                    "gasLimit":hex(header.gas_limit),
                    "gasUsed":hex(header.gas_used),
                    "baseFeePerGas":"0x0",
                    "timestamp":"0x644b949c",
                    # "transactions":["0xed65f0ac3506915ba5cc0a5da762b651816928fcc272e6f828e5f1f823f4713d"],
                    "transactions":[],
                    "uncles":[]
            }}


        elif req.get('method') == 'eth_getBalance':
            address = web3.Web3.to_checksum_address(req['params'][0])
            account = state._main_trie._data[web3.Web3.to_bytes(hexstr=address)]
            print(account)
            balance = int(account.balance)
            resp = {'jsonrpc':'2.0', 'result': hex(balance), 'id':rpc_id}

        elif req.get('method') == 'eth_getTransactionReceipt':
            tx_hash = req['params'][0][2:]
            print(tx_hash)
            tx_bytes=bytes.fromhex(tx_hash)
            receipt=trie_get(chain.state._receipt_trie,tx_bytes)
            block_number = receipt.block_number
            contract_address='0x'+receipt.contract_address.hex() if receipt.contract_address.hex() else None
            to_address = '0x' + receipt.to.hex() if receipt.to.hex() else None

            result = {
                'transactionHash':'0x' + tx_hash,
                'transactionIndex': hex(receipt.transaction_index),
                'blockHash': '0x' + hash_block(chain.blocks[block_number].header).hex(),
                'blockNumber': hex(block_number),
                'from': '0x' + receipt.from_addr.hex(),
                'to': to_address,
                'cumulativeGasUsed': hex(receipt.cumulative_gas_used),
                'gasUsed':hex(receipt.gas_used),
                'status': '0x1' if receipt.status else '0x0',
                'contractAddress': contract_address,
                'logs': '0x' + (b''.join(receipt.logs)).hex(),
                'logsBloom': '0x' + receipt.bloom.hex()
            }
            resp = {'jsonrpc':'2.0', 'result': result, 'id': rpc_id}

        elif req.get('method') == 'eth_getCode':
            resp = {'jsonrpc':'2.0', 'result': '0x0208', 'id': rpc_id}

        elif req.get('method') == 'eth_gasPrice':
            resp = {'jsonrpc':'2.0', 'result': '0x0', 'id': rpc_id}

        elif req.get('method') == 'eth_estimateGas':
            resp = {'jsonrpc':'2.0', 'result': '0x5208', 'id': rpc_id} # 21000 gas

        elif req.get('method') == 'eth_maxPriorityFeePerGas':
            resp = {'jsonrpc':'2.0', 'result': '0x0', 'id': rpc_id}

        elif req.get('method') == 'eth_getTransactionCount':
            address = req['params'][0].lower()
            account = state._main_trie._data[web3.Web3.to_bytes(hexstr=address)]

            nonce = account.nonce

            resp = {'jsonrpc':'2.0', 'result': hex(nonce), 'id': rpc_id}

        elif req.get('method') == 'eth_getBlockByHash':
            resp = {'jsonrpc':'2.0', 'result': '0x0', 'id': rpc_id}

        elif req.get('method') == 'eth_sendTransaction':
            tx, tx_hash = miner.json_transaction(req)
            miner.add_transaction(tx)
            miner.mine_block()
            resp = {'jsonrpc': '2.0', 'result': '0x' + tx_hash.hex(), 'id': rpc_id}

        elif req.get('method') == 'eth_getTransactionByHash':
            tx_hash=req["params"][0][2:]
            # print(tx_hash)
            tx_bytes=bytes.fromhex(tx_hash)
            receipt = trie_get(chain.state._receipt_trie, tx_bytes)
            transaction = trie_get(chain.state._transaction_trie, tx_bytes)
            block_number = receipt.block_number
            to_address='0x'+ transaction.to.hex() if transaction.to.hex() else None

            resp = {'jsonrpc': '2.0', 'result': {
                "blockHash": '0x' + hash_block(chain.blocks[block_number].header).hex(),
                "blockNumber": hex(block_number),
                "chainId": int(chain.chain_id),
                "from": '0x' + receipt.from_addr.hex(),
                "gas":  hex(receipt.gas_used),
                "gasPrice":  hex(receipt.gas_price),
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

            # print(resp)

        elif req.get('method') == 'eth_sendRawTransaction':
            params = req.get('params', [])
            raw_tx_hex = params[0]
            # print('raw_tx_hex', raw_tx_hex)
            raw_tx_bytes = web3.Web3.to_bytes(hexstr=raw_tx_hex)
            # print('raw_tx_bytes', raw_tx_bytes)
            tx_list, vrs = eth_tx.eth_rlp2list(raw_tx_bytes)
            if len(tx_list) == 8:
                tx = eth_account._utils.typed_transactions.DynamicFeeTransaction.from_bytes(hexbytes.HexBytes(raw_tx_hex))
                # tx = eth_account._utils.typed_transactions.TypedTransaction(transaction_type=2, transaction=tx)
                tx_hash = tx.hash()
                vrs = tx.vrs()
                tx_to = web3.Web3.to_checksum_address(tx.as_dict()['to'])
                tx_data = web3.Web3.to_hex(tx.as_dict()['data'])
                tx_nonce = web3.Web3.to_int(tx.as_dict()['nonce'])
            else:
                tx = eth_account._utils.legacy_transactions.Transaction.from_bytes(raw_tx_bytes)
                tx_hash = eth_account._utils.signing.hash_of_signed_transaction(tx)
                vrs = eth_account._utils.legacy_transactions.vrs_from(tx)
                tx_to = web3.Web3.to_checksum_address(tx.to)
                tx_data = web3.Web3.to_hex(tx.data)
                tx_nonce = tx.nonce

            tx_from = eth_account.Account._recover_hash(tx_hash, vrs=vrs).lower()
            # latest_block_height = chain.get_latest_block_number()

            # _state = state.get_state()
            # _state.block_number = latest_block_height
            # contracts.vm_map[tx_to].global_vars['_block_number'] = _state.block_number
            # contracts.vm_map[tx_to].global_vars['_call'] = state.call
            # contracts.vm_map[tx_to].global_vars['_state'] = _state
            # _state.sender = tx_from
            # contracts.vm_map[tx_to].global_vars['_sender'] = tx_from
            # _state.contract_address = tx_to
            # contracts.vm_map[tx_to].global_vars['_self'] = _state.contract_address


            # result = '0x'
            # func_sig = tx_data[:10]
            # # print(interface_map[func_sig], tx_data)
            # func_params_data = tx_data[10:]
            # func_params = [func_params_data[i:i+64] for i in range(0, len(func_params_data)-2, 64)]
            # print('func', contracts.interface_map[tx_to][func_sig].__name__, func_params)
            # func_params = []
            # for k, v in zip(contracts.params_map[tx_to][contracts.interface_map[tx_to][func_sig].__name__], func_params):
            #     # print('type', k, v)
            #     if k == 'address':
            #         func_params.append(web3.Web3.to_checksum_address('0x'+v[24:]))
            #     elif k == 'uint256':
            #         func_params.append(web3.Web3.to_int(hexstr=v))

            # # result = interface_map[func_sig](*func_params)
            # contracts.vm_map[tx_to].run(func_params, contracts.interface_map[tx_to][func_sig].__name__)

            prev_hash = '0'*64
            db = database.get_conn()
            it = db.iteritems()
            console.log(('subchain_%s_' % tx_from).encode('utf8'))
            it.seek(('subchain_%s_' % tx_from).encode('utf8'))
            for subchain_key, subchain_value in it:
                print('eth_sendRawTransaction', subchain_key, subchain_value)
                if not subchain_key.decode('utf8').startswith('subchain_%s_' % tx_from):
                    prev_hash = '0'*64
                    assert 1 == tx_nonce
                    break

                subchain_key_list = subchain_key.decode('utf8').split('_')
                reversed_height = int(subchain_key_list[2])
                count = setting.REVERSED_NO - reversed_height
                print(reversed_height, count, tx_nonce)
                assert count + 1 == tx_nonce

                tx = tornado.escape.json_decode(subchain_value)
                print('eth_sendRawTransaction tx', tx)
                prev_hash = tx[0]
                break

            print('eth_sendRawTransaction prev_hash', prev_hash)

            # _msg_header, block_hash, prev_hash, sender, receiver, height, data, timestamp, signature = seq
            # tx_list, vrs = eth_rlp2list(raw_tx_bytes)
            tx_list_json = json.dumps(tx_list)
            new_timestamp = time.time()
            block_hash_obj = hashlib.sha256((prev_hash + tx_from + tx_to + str(tx_nonce) + tx_list_json + str(new_timestamp)).encode('utf8'))
            block_hash = block_hash_obj.hexdigest()
            signature_obj = eth_account.Account._keys.Signature(vrs=vrs)
            signature = signature_obj.to_hex()

            seq = ['NEW_SUBCHAIN_BLOCK', block_hash, prev_hash, 'eth', new_timestamp, tx_list, signature]
            chain.new_subchain_block(seq)
            tree.forward(seq)

            resp = {'jsonrpc':'2.0', 'result': '0x%s' % block_hash, 'id': rpc_id}

        elif req.get('method') == 'eth_call':

            params = req.get('params', [])

            #try:
            #if len(params) > 0:
                #if 'to' in params[0] and 'data' in params[0] and params[0]['to'].lower() in contracts.contract_map:
                    # contract = contract_map[params[0]['to'].lower()]
            tx_to = params[0]['to']
            tx_data = params[0]['data'].replace('0x', '')
            contract_account= state._main_trie._data[web3.Web3.to_bytes(hexstr=tx_to)]
            result=contract_account.code
            resp = {'jsonrpc': '2.0', 'result': '0x' + result.hex(), 'id': rpc_id}
            #
            # #if tx_data.startswith('0x01ffc9a7'): # 80ac58cd for 721 and d9b67a26 for 1155
            #     #resp = {"jsonrpc":"2.0","id":rpc_id,"error":{"code":-32603,"message":"Error: Transaction reverted without a reason string","data":{"message":"Error: Transaction reverted without a reason string","data":"0x"}}}
            # #    resp = {"jsonrpc":"2.0","id":rpc_id,"error":-32603}
            #
            # if tx_to in contracts.vm_map:
            #     latest_block_height = chain.get_latest_block_number()
            #
            #     state.block_number = latest_block_height
            #     contracts.vm_map[tx_to].global_vars['_block_number'] = state.block_number
            #     contracts.vm_map[tx_to].global_vars['_call'] = state.call
            #     contracts.vm_map[tx_to].global_vars['_get'] = state.get
            #     contracts.vm_map[tx_to].global_vars['_put'] = state.put
            #     # contracts.vm_map[tx_to].global_vars['_sender'] = tx_from
            #     state.contract_address = tx_to
            #     contracts.vm_map[tx_to].global_vars['_self'] = state.contract_address
            #
            #     func_sig = tx_data[:8]
            #     # print(contracts.interface_map[tx_to][func_sig], tx_data)
            #     func_params_data = tx_data[8:]
            #     # result = interface_map[func_sig](*func_params)
            #
            #     func_params_type = contracts.params_map[tx_to][contracts.interface_map[tx_to][func_sig].__name__]
            #     # console.log(func_params_type)
            #     # console.log(func_params_data)
            #     func_params = eth_abi.decode(func_params_type, hexbytes.HexBytes(func_params_data))
            #     # console.log(func_params)
            #
            #     value = contracts.vm_map[tx_to].run(func_params, contracts.interface_map[tx_to][func_sig].__name__)
            #     func_return_type = contracts.return_map[tx_to][contracts.interface_map[tx_to][func_sig].__name__]
            #     console.log(func_return_type, value)
            #     result = eth_abi.encode([func_return_type], [value])
            #     print('result', result)

                # resp = {'jsonrpc':'2.0', 'result': '0x'+result.hex(), 'id': rpc_id}

            #except:
            #    resp = {'jsonrpc':'2.0', 'result': '0x', 'id': rpc_id}

            # else:
            #     #resp = {"jsonrpc":"2.0","id":rpc_id,"error":{"code":-32603,"message":"Error: Transaction reverted without a reason string","data":{"message":"Error: Transaction reverted without a reason string","data":"0x"}}}
            #     resp = {"jsonrpc":"2.0","id":rpc_id,"error":-32603}
            #     #resp = {'jsonrpc':'2.0', 'result': '0x0000000000000000000000000000000000000000000000000000000000000000', 'id': rpc_id}
            # print('resp', resp)

        elif req.get('method') == 'eth_feeHistory':
            resp = {'jsonrpc':'2.0', 'result': {}, 'id': rpc_id}
        #     # db = database.get_conn()
        #     # it = db.iteritems()
        #     # it.seek(('headerblock_').encode('utf8'))
        #     # no = 0
        #     # for k, v in it:
        #     #     print('eth_feeHistory', k, v)
        #     #     if k.decode('utf8').startswith('headerblock_'):
        #     #         ks = k.decode('utf8').split('_')
        #     #         reverse_no = int(ks[1])
        #     #         no = setting.REVERSED_NO - reverse_no
        #     #         oldest = ks[2]
        #     #     break

        #     resp = {'jsonrpc':'2.0', 'result': {
        #         "baseFeePerGas": [
        #             "0x0",
        #             "0x0",
        #             "0x0",
        #             "0x0",
        #             "0x0"
        #         ],
        #         "gasUsedRatio": [
        #             0.5290747666666666,
        #             0.49240453333333334,
        #             0.4615576,
        #             0.49407083333333335,
        #             0.4669053
        #         ],
        #         "oldestBlock": "0xfab8ac",
        #         "reward": [
        #             [
        #                 "0x59682f00",
        #                 "0x59682f00"
        #             ],
        #             [
        #                 "0x59682f00",
        #                 "0x59682f00"
        #             ],
        #             [
        #                 "0x3b9aca00",
        #                 "0x59682f00"
        #             ],
        #             [
        #                 "0x510b0870",
        #                 "0x59682f00"
        #             ],
        #             [
        #                 "0x3b9aca00",
        #                 "0x59682f00"
        #             ]
        #         ]
        #     }, 'id': rpc_id}

        elif req.get('method') == 'web3_clientVersion':
            resp = {'jsonrpc':'2.0', 'result': 'BitPoW', 'id': rpc_id}

        elif req.get('method') == 'eth_chainId':
            resp = {'jsonrpc':'2.0', 'result': hex(setting.CHAIN_ID), 'id':rpc_id}

        elif req.get('method') == 'net_version':
            resp = {'jsonrpc':'2.0', 'result': str(setting.CHAIN_ID),'id': rpc_id}

        elif req.get('method') == 'evm_snapshot':
            resp = {'jsonrpc':'2.0', 'result': str(setting.CHAIN_ID),'id': rpc_id}

        elif req.get('method') == 'eth_accounts':
            resp = {'jsonrpc':'2.0', 'result': [
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
        else:
            logger.error("unknown post method:%s"%req.get('method'))
            resp = {'jsonrpc': '2.0', 'result': {}, 'id': rpc_id}
        logger.info(resp)
        self.write(tornado.escape.json_encode(resp))


class Application(tornado.web.Application):
    def __init__(self):
        handlers = [
                    (r"/", EthRpcHandler),
                ]
        settings = {"debug":True}

        tornado.web.Application.__init__(self, handlers, **settings)


if __name__ == '__main__':
    server = Application()
    server.listen(8545, '127.0.0.1')
    tornado.ioloop.IOLoop.instance().start()

