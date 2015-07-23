import os
from uuid import uuid4
from ecdsa import SigningKey
import time
from pmpi.block import Block
from pmpi.block import BlockRev
from pmpi.core import close_database, initialise_database
from pmpi.operation import OperationRev, Operation
from pmpi.utils import sign_object
from pmpi.public_key import PublicKey


def test():
    try:
        os.remove('test_database_file')
    except OSError:
        pass
    initialise_database('test_database_file')

    obj_private_key = SigningKey.generate()
    obj_public_key = PublicKey.from_signing_key(obj_private_key)
    obj_uuids = [uuid4() for _ in range(3)]

    obj_operations = [[
        Operation(OperationRev(),
                  obj_uuids[0], 'http://example0.com/v0/', [obj_public_key]),
        Operation(OperationRev(),
                  obj_uuids[1], 'http://example1.com/v0/', [obj_public_key])
    ]]

    for op in obj_operations[0]:
        sign_object(obj_public_key, obj_private_key, op)

    obj_operations.append([
        Operation(OperationRev.from_revision(obj_operations[0][0]),
                  obj_uuids[0], 'http://example0.com/v1/', [obj_public_key]),
        Operation(OperationRev.from_revision(obj_operations[0][1]),
                  obj_uuids[1], 'http://example1.com/v1/', [obj_public_key]),
        Operation(OperationRev(),
                  obj_uuids[2], 'http://example2.com/v0/', [obj_public_key])
    ])

    for op in obj_operations[1]:
        sign_object(obj_public_key, obj_private_key, op)

    obj_operations.append([
        Operation(OperationRev.from_revision(obj_operations[1][0]),
                  obj_uuids[0], 'http://example0.com/v2/', [obj_public_key]),
        Operation(OperationRev.from_revision(obj_operations[1][1]),
                  obj_uuids[1], 'http://example1.com/v2/', [obj_public_key])
    ])

    for op in obj_operations[2]:
        sign_object(obj_public_key, obj_private_key, op)

    obj_operations.append([
        Operation(OperationRev.from_revision(obj_operations[1][1]),
                  obj_uuids[1], 'http://alternative1.com/', [obj_public_key]),
        Operation(OperationRev.from_revision(obj_operations[1][2]),
                  obj_uuids[2], 'http://alternative2.com/', [obj_public_key])
    ])

    for op in obj_operations[3]:
        sign_object(obj_public_key, obj_private_key, op)

    timestamp = int(time.time()) - 100

    obj_blocks = [Block.from_operations_list(BlockRev(), timestamp, obj_operations[0])]
    obj_blocks[0].mine()
    sign_object(obj_public_key, obj_private_key, obj_blocks[0])
    obj_blocks.append(
        Block.from_operations_list(BlockRev.from_revision(obj_blocks[0]), timestamp + 20, obj_operations[1]))
    obj_blocks[1].mine()
    sign_object(obj_public_key, obj_private_key, obj_blocks[1])
    obj_blocks.append(
        Block.from_operations_list(BlockRev.from_revision(obj_blocks[1]), timestamp + 40, obj_operations[2]))
    obj_blocks[2].mine()
    sign_object(obj_public_key, obj_private_key, obj_blocks[2])
    obj_blocks.append(
        Block.from_operations_list(BlockRev.from_revision(obj_blocks[1]), timestamp + 60, obj_operations[3]))
    obj_blocks[3].mine()
    sign_object(obj_public_key, obj_private_key, obj_blocks[3])

    for block in obj_blocks:
        block.put()

    for block in obj_blocks:
        new_block = Block.get(block.hash())
        assert new_block.hash() == block.hash()

    for block in obj_blocks[:2]:
        try:
            block.remove()
            raise AssertionError
        except Block.ChainOperationBlockedError:
            pass

    assert sorted(Block.get_revision_id_list()) == sorted([block.hash() for block in obj_blocks])

    obj_blocks[2].remove()

    for block in obj_blocks[:2]:
        try:
            block.remove()
            raise AssertionError
        except Block.ChainOperationBlockedError:
            pass

    obj_blocks[3].remove()

    try:
        obj_blocks[0].remove()
        raise AssertionError
    except Block.ChainOperationBlockedError:
        pass

    obj_blocks[1].remove()
    obj_blocks[0].remove()

    for block in obj_blocks:
        try:
            block.remove()
            raise AssertionError
        except Block.DoesNotExist:
            pass

    assert Block.get_revision_id_list() == []

    close_database()
    os.remove('test_database_file')


print("hello")

test()

print("goodbye")
