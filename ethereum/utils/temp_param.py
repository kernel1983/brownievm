'''
Due to the fact that the sources of some parameters are still unclear at present,
temporarily use the provisional parameters as substitutes for the time being.
will refine them later.
'''


from ethereum_types.numeric import Uint, U256
from ethereum_types.bytes import Bytes20

from ethereum.utils.hexadecimal import hex_to_bytes

# Transaction,Temporary data related to the Transaction
TRANSACTION_v = U256(27)
TRANSACTION_r = U256(1)
TRANSACTION_s = U256(1)

# Header, Temporary data related to the Header
HEADER_difficulty = Uint(int("0x400000000", 16))
HEADER_gas_limit = Uint(3000000)
HEADER_extra_data = b''

#Block, Temporary data related to the block
BLOCK_gas_limit=Uint(10*10e9)   #The gas_limit value set in the mainnet.json file is too low.

# Environment Temporary data related to the Environment
ENVIRONMENT_gas_limit = Uint(10 * 10**9)
ENVIRONMENT_gas_price = Uint(20 * 10**9)

# Coinbase address
COINBASE_address = Bytes20(hex_to_bytes("0x001d14804b399c6ef80e64576f657660804fec0b"))