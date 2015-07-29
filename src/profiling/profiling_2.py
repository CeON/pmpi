import os
from uuid import uuid4
from unittest.mock import patch

from ecdsa import SigningKey

from pmpi.block import Block
from pmpi.block import BlockRev
from pmpi.blockchain import BlockChain
from pmpi.core import close_database, initialise_database, get_blockchain
from pmpi.identifier import Identifier
from pmpi.operation import OperationRev, Operation
from pmpi.utils import sign_object
from pmpi.public_key import PublicKey

patch.object = patch.object


def add_operations(uuids, private_keys, public_keys):
    """
    create operations:
    for uuid[0]: op[0] -> op[2] -> op[6] -> op[8];
    for uuid[1]: op[1] -> op[3] -> op[4];
    for uuid[2]: op[5] -> op[7] -> op[9]
    """
    ops = [
        Operation(OperationRev(), uuids[0], 'http://example1.com/', [public_keys[0]]),
        Operation(OperationRev(), uuids[1], 'http://example2.com/', [public_keys[1]]),
    ]

    sign_object(public_keys[0], private_keys[0], ops[0])
    sign_object(public_keys[0], private_keys[0], ops[1])

    ops.extend([
        Operation(OperationRev.from_obj(ops[0]), uuids[0],
                  'http://example1.com/v2/', [public_keys[0]]),
        Operation(OperationRev.from_obj(ops[1]), uuids[1],
                  'http://example2.com/v2/', [public_keys[1]])
    ])

    sign_object(public_keys[0], private_keys[0], ops[2])
    sign_object(public_keys[1], private_keys[1], ops[3])

    ops.append(
        Operation(OperationRev.from_obj(ops[3]), uuids[1],
                  'http://example2.com/v3/', [public_keys[1]])
    )

    sign_object(public_keys[1], private_keys[1], ops[4])

    ops.extend([
        Operation(OperationRev(), uuids[2],
                  'http://example3.com/', [public_keys[1], public_keys[2]]),
        Operation(OperationRev.from_obj(ops[2]), uuids[0],
                  'http://example1.com/v3/', [public_keys[0], public_keys[2]])
    ])

    sign_object(public_keys[2], private_keys[2], ops[5])
    sign_object(public_keys[0], private_keys[0], ops[6])

    ops.extend([
        Operation(OperationRev.from_obj(ops[5]), uuids[2],
                  'http://example3.com/v2/', [public_keys[2]]),
        Operation(OperationRev.from_obj(ops[6]), uuids[0],
                  'http://example1.com/v4/', [public_keys[2]])
    ])

    sign_object(public_keys[1], private_keys[1], ops[7])
    sign_object(public_keys[2], private_keys[2], ops[8])

    ops.append(
        Operation(OperationRev.from_obj(ops[7]), uuids[2],
                  'http://example3.com/v3/', [public_keys[2]])
    )

    sign_object(public_keys[2], private_keys[2], ops[9])

    return ops


def add_blocks(uuids, private_keys, public_keys):
    """
    create blocks:
    blocks[0] -> blocks[1] -> blocks[2] -> blocks[3] -> blocks[5]
                                       \-> blocks[4] -> blocks[6]
    """
    ops = add_operations(uuids, private_keys, public_keys)
    start_time = 42
    blocks = [Block.from_operations_list(BlockRev(), start_time, [ops[0], ops[1]])]
    blocks[0].mine()
    sign_object(public_keys[0], private_keys[0], blocks[0])
    blocks.append(Block.from_operations_list(BlockRev.from_obj(blocks[0]), start_time + 10, [ops[2], ops[6]]))
    blocks[1].mine()
    sign_object(public_keys[0], private_keys[0], blocks[1])
    blocks.append(Block.from_operations_list(BlockRev.from_obj(blocks[1]), start_time + 20, [ops[3], ops[5]]))
    blocks[2].mine()
    sign_object(public_keys[0], private_keys[0], blocks[2])
    blocks.append(Block.from_operations_list(BlockRev.from_obj(blocks[2]), start_time + 30, [ops[8], ops[4]]))
    blocks[3].mine()
    sign_object(public_keys[0], private_keys[0], blocks[3])
    blocks.append(Block.from_operations_list(BlockRev.from_obj(blocks[2]), start_time + 40, [ops[4], ops[7]]))
    blocks[4].mine()
    sign_object(public_keys[0], private_keys[0], blocks[4])
    blocks.append(Block.from_operations_list(BlockRev.from_obj(blocks[3]), start_time + 50, [ops[7], ops[9]]))
    blocks[5].mine()
    sign_object(public_keys[0], private_keys[0], blocks[5])
    blocks.append(Block.from_operations_list(BlockRev.from_obj(blocks[4]), start_time + 60, [ops[8], ops[9]]))
    blocks[6].mine()
    sign_object(public_keys[0], private_keys[0], blocks[6])

    return blocks


def test():
    initialise_database('test_database_file')

    private_keys = [SigningKey.generate() for _ in range(3)]
    public_keys = [PublicKey.from_signing_key(private_key) for private_key in private_keys]
    uuids = [uuid4() for _ in range(3)]

    # BUILD    
    # blocks = add_blocks()
    #
    # for block in blocks:
    #     block.put()
    #
    # block_chain = BlockChain()
    #
    # block_chain_records_pattern = [
    #     BlockChain.Record(1, b'\x00'*32, [blocks[1].id]),
    #     BlockChain.Record(2, blocks[0].id, [blocks[2].id]),
    #     BlockChain.Record(3, blocks[1].id, sorted([blocks[3].id, blocks[4].id])),
    #     BlockChain.Record(4, blocks[2].id, [blocks[5].id]),
    #     BlockChain.Record(4, blocks[2].id, [blocks[6].id]),
    #     BlockChain.Record(5, blocks[3].id, []),
    #     BlockChain.Record(5, blocks[4].id, [])
    # ]
    #
    # for i in range(6):
    #     assertEqual(block_chain.get(blocks[i].id), block_chain_records_pattern[i])

    # UPDATE BLOCKS
    # blocks = add_blocks()
    # bc = get_blockchain()
    #
    # with patch.object(BlockChain, '_get_new_blocks', return_value=blocks):
    #     bc.update_blocks()
    #
    # assertEqual(bc.max_depth, 5)
    # assertEqual(bc.head, blocks[5].id)
    #
    # for block in blocks:
    #     assertEqual(bc.get(block.id).previous_id, block.previous_block_rev.id)

    # MULTIPLE UPDATE BLOCKS
    # blocks = add_blocks()
    # bc = get_blockchain()
    #
    # def patched_update_blocks(block_list):
    #     with patch.object(BlockChain, '_get_new_blocks', return_value=block_list):
    #         bc.update_blocks()
    #
    # for blocks_to_add, max_depth, head in (
    #         (blocks[0:2], 2, blocks[1].id),
    #         (blocks[2:3], 3, blocks[2].id),
    #         (blocks[4:5], 4, blocks[4].id),
    #         (blocks[3:4], 4, blocks[4].id),
    #         (blocks[5:6], 5, blocks[5].id),
    #         (blocks[6:7], 5, blocks[5].id)
    # ):
    #     patched_update_blocks(blocks_to_add)
    #     assertEqual(bc.max_depth, max_depth)
    #     assertEqual(bc.head, head)

    # DELETE

    blocks = add_blocks(uuids, private_keys, public_keys)
    bc = get_blockchain()

    with patch.object(BlockChain, '_get_new_blocks', return_value=blocks):
        bc.update_blocks()

    try:
        blocks[4].remove()
        raise AssertionError
    except Block.ChainOperationBlockedError:
        pass

    assert bc.max_depth == 5
    assert bc.head == blocks[5].id

    for block_to_remove, max_depth, heads in (
            (blocks[5], 5, [blocks[6].id]),
            (blocks[6], 4, [blocks[3].id, blocks[4].id]),
            (blocks[4], 4, [blocks[3].id]),
            (blocks[3], 3, [blocks[2].id]),
            (blocks[2], 2, [blocks[1].id]),
            (blocks[1], 1, [blocks[0].id]),
            (blocks[0], 0, [BlockRev().id])
    ):
        block_to_remove.remove()
        assert bc.max_depth == max_depth
        assert bc.head in heads

    with patch.object(BlockChain, '_get_new_blocks', return_value=blocks):
        bc.update_blocks()

    assert bc.max_depth == 5
    assert bc.head == blocks[5].id

    assert sorted([op.uuid for op in blocks[0].operations + blocks[2].operations[1:2]]) == sorted(
        Identifier.get_uuid_list())

    close_database()
    os.remove('test_database_file')


test()
