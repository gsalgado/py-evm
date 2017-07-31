from evm import EVM

from evm.vm.flavors import (
    QuorumVM,
)


# Plan is to
#  1. implement Quorum's consensus mechanism
#    - Maybe a good stepping stone is to support a generic PoA consensus.
#      https://github.com/paritytech/parity/wiki/Proof-of-Authority-Chains
#  2. implement private transactions, probably using constellation as well
#

# NOTES:
#  - Figure out how to force gas-price to always be 0. In quorum they had to
#    modify all the APIs in internal/ethapi/api.go
#  - Do we have a min gas price? Would need to be able to disable that or else
#    need to change the code like in quorum

def validate_state(evm, block):
    # call getCanonHash(block.number) in the smart contract to check that it
    # matches block.parent_hash
    # BlockValidator.ValidateState() in quorum
    pass


def validate_extra_data(evm, header):
    # call isBlockMaker(addr) with the address extracted from the pubkey used
    # in the signature stored in extra_data.
    # ValidateExtraData in quorum
    pass


def validate_block(evm, block):
    validate_extra_data(evm, block.header)
    validate_state(evm, block)


QuorumEVM = EVM.configure(
    'QuorumEVM',
    vm_configuration=(
        (0, QuorumVM),
    ),
    validate_block=validate_block,
)
