import os
from unittest.case import TestCase
from unittest.mock import patch
from uuid import uuid4
from ecdsa.keys import SigningKey
from pmpi.block import Block, BlockRev
from pmpi.blockchain import BlockChain
from pmpi.core import initialise_database, close_database, get_blockchain
from pmpi.identifier import Identifier
from pmpi.operation import Operation, OperationRev
from pmpi.utils import sign_object
from pmpi.public_key import PublicKey

patch.object = patch.object


class TestBlockChain(TestCase):
    def setUp(self):
        initialise_database('test_database_file')

        self.private_keys = [SigningKey.generate() for _ in range(3)]
        self.public_keys = [PublicKey.from_signing_key(private_key) for private_key in self.private_keys]
        self.uuids = [uuid4() for _ in range(3)]

    def add_operations(self):
        """
        create operations:
        for uuid[0]: op[0] -> op[2] -> op[6] -> op[8];
        for uuid[1]: op[1] -> op[3] -> op[4];
        for uuid[2]: op[5] -> op[7] -> op[9]
        """
        ops = [
            Operation(OperationRev(), self.uuids[0], 'http://example1.com/', [self.public_keys[0]]),
            Operation(OperationRev(), self.uuids[1], 'http://example2.com/', [self.public_keys[1]]),
        ]

        sign_object(self.public_keys[0], self.private_keys[0], ops[0])
        sign_object(self.public_keys[0], self.private_keys[0], ops[1])

        ops.extend([
            Operation(OperationRev.from_obj(ops[0]), self.uuids[0],
                      'http://example1.com/v2/', [self.public_keys[0]]),
            Operation(OperationRev.from_obj(ops[1]), self.uuids[1],
                      'http://example2.com/v2/', [self.public_keys[1]])
        ])

        sign_object(self.public_keys[0], self.private_keys[0], ops[2])
        sign_object(self.public_keys[1], self.private_keys[1], ops[3])

        ops.append(
            Operation(OperationRev.from_obj(ops[3]), self.uuids[1],
                      'http://example2.com/v3/', [self.public_keys[1]])
        )

        sign_object(self.public_keys[1], self.private_keys[1], ops[4])

        ops.extend([
            Operation(OperationRev(), self.uuids[2],
                      'http://example3.com/', [self.public_keys[1], self.public_keys[2]]),
            Operation(OperationRev.from_obj(ops[2]), self.uuids[0],
                      'http://example1.com/v3/', [self.public_keys[0], self.public_keys[2]])
        ])

        sign_object(self.public_keys[2], self.private_keys[2], ops[5])
        sign_object(self.public_keys[0], self.private_keys[0], ops[6])

        ops.extend([
            Operation(OperationRev.from_obj(ops[5]), self.uuids[2],
                      'http://example3.com/v2/', [self.public_keys[2]]),
            Operation(OperationRev.from_obj(ops[6]), self.uuids[0],
                      'http://example1.com/v4/', [self.public_keys[2]])
        ])

        sign_object(self.public_keys[1], self.private_keys[1], ops[7])
        sign_object(self.public_keys[2], self.private_keys[2], ops[8])

        ops.append(
            Operation(OperationRev.from_obj(ops[7]), self.uuids[2],
                      'http://example3.com/v3/', [self.public_keys[2]])
        )

        sign_object(self.public_keys[2], self.private_keys[2], ops[9])

        return ops

    def add_blocks(self, ops):
        """
        create blocks:
        blocks[0] -> blocks[1] -> blocks[2] -> blocks[3] -> blocks[5]
                                           \-> blocks[4] -> blocks[6]
        """
        start_time = 42
        blocks = [Block.from_operations_list(BlockRev(), start_time, [ops[0], ops[1]])]
        blocks[0].mine()
        sign_object(self.public_keys[0], self.private_keys[0], blocks[0])
        blocks.append(Block.from_operations_list(BlockRev.from_obj(blocks[0]), start_time + 10, [ops[2], ops[6]]))
        blocks[1].mine()
        sign_object(self.public_keys[0], self.private_keys[0], blocks[1])
        blocks.append(Block.from_operations_list(BlockRev.from_obj(blocks[1]), start_time + 20, [ops[3], ops[5]]))
        blocks[2].mine()
        sign_object(self.public_keys[0], self.private_keys[0], blocks[2])
        blocks.append(Block.from_operations_list(BlockRev.from_obj(blocks[2]), start_time + 30, [ops[8], ops[4]]))
        blocks[3].mine()
        sign_object(self.public_keys[0], self.private_keys[0], blocks[3])
        blocks.append(Block.from_operations_list(BlockRev.from_obj(blocks[2]), start_time + 40, [ops[4], ops[7]]))
        blocks[4].mine()
        sign_object(self.public_keys[0], self.private_keys[0], blocks[4])
        blocks.append(Block.from_operations_list(BlockRev.from_obj(blocks[3]), start_time + 50, [ops[7], ops[9]]))
        blocks[5].mine()
        sign_object(self.public_keys[0], self.private_keys[0], blocks[5])
        blocks.append(Block.from_operations_list(BlockRev.from_obj(blocks[4]), start_time + 60, [ops[8], ops[9]]))
        blocks[6].mine()
        sign_object(self.public_keys[0], self.private_keys[0], blocks[6])

        return blocks

    def test_build_blocks(self):
        blocks = self.add_blocks(self.add_operations())

        for block in blocks:
            block.put()

        block_chain = BlockChain()

        block_chain_records_pattern = [
            BlockChain.Record(1, b'\x00'*32, [blocks[1].id]),
            BlockChain.Record(2, blocks[0].id, [blocks[2].id]),
            BlockChain.Record(3, blocks[1].id, sorted([blocks[3].id, blocks[4].id])),
            BlockChain.Record(4, blocks[2].id, [blocks[5].id]),
            BlockChain.Record(4, blocks[2].id, [blocks[6].id]),
            BlockChain.Record(5, blocks[3].id, []),
            BlockChain.Record(5, blocks[4].id, [])
        ]

        for i in range(6):
            self.assertEqual(block_chain.get(blocks[i].id), block_chain_records_pattern[i])

    def test_only_one_genesis_block(self):
        ops = self.add_operations()
        blocks = [
            Block.from_operations_list(BlockRev(), 42, [ops[1], ops[3], ops[4]]),
            Block.from_operations_list(BlockRev(), 43, [ops[5], ops[7], ops[9]])
        ]

        for block in blocks:
            block.mine()
            sign_object(self.public_keys[0], self.private_keys[0], block)

        blocks[0].put()

        for block in blocks:
            with self.assertRaisesRegex(Block.GenesisBlockDuplication, "trying to create multiple genesis blocks"):
                block.put()

    def test_update_blocks(self):
        blocks = self.add_blocks(self.add_operations())
        bc = get_blockchain()

        with patch.object(BlockChain, '_get_new_blocks', return_value=blocks):
            bc.update_blocks()

        self.assertEqual(bc.max_depth, 5)
        self.assertEqual(bc.head, blocks[5].id)

        for block in blocks:
            self.assertEqual(bc.get(block.id).previous_id, block.previous_block_rev.id)

    def test_multiple_update_blocks(self):
        blocks = self.add_blocks(self.add_operations())
        bc = get_blockchain()

        def patched_update_blocks(block_list):
            with patch.object(BlockChain, '_get_new_blocks', return_value=block_list):
                bc.update_blocks()

        for blocks_to_add, max_depth, head in (
                (blocks[0:2], 2, blocks[1].id),
                (blocks[2:3], 3, blocks[2].id),
                (blocks[4:5], 4, blocks[4].id),
                (blocks[3:4], 4, blocks[4].id),
                (blocks[5:6], 5, blocks[5].id),
                (blocks[6:7], 5, blocks[5].id)
        ):
            patched_update_blocks(blocks_to_add)
            self.assertEqual(bc.max_depth, max_depth)
            self.assertEqual(bc.head, head)

    def test_delete_blocks(self):
        blocks = self.add_blocks(self.add_operations())
        bc = get_blockchain()

        with patch.object(BlockChain, '_get_new_blocks', return_value=blocks):
            bc.update_blocks()

        with self.assertRaisesRegex(Block.ChainOperationBlockedError, "can't remove: blocked by another block"):
            blocks[4].remove()

        self.assertEqual(bc.max_depth, 5)
        self.assertEqual(bc.head, blocks[5].id)

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
            self.assertEqual(bc.max_depth, max_depth)
            self.assertIn(bc.head, heads)

        with patch.object(BlockChain, '_get_new_blocks', return_value=blocks):
            bc.update_blocks()

        self.assertEqual(bc.max_depth, 5)
        self.assertEqual(bc.head, blocks[5].id)

        self.assertCountEqual([op.uuid for op in blocks[0].operations + blocks[2].operations[1:2]],
                              Identifier.get_uuid_list())

    def test_wrong_operations(self):
        operations = self.add_operations()
        blocks = self.add_blocks(operations)
        bc = get_blockchain()

        with patch.object(BlockChain, '_get_new_blocks', return_value=blocks):
            bc.update_blocks()

        with self.assertRaisesRegex(Block.VerifyError, "some of the new operations have been added to the block already"):
            blocks[5].extend_operations([operations[9]])

        illegal_operation = Operation(operations[7].get_rev(), operations[7].uuid, 'illegal address', [])
        sign_object(self.public_keys[2], self.private_keys[2], illegal_operation)

        blocks[5].extend_operations([illegal_operation])
        blocks[5].mine()

        with self.assertRaisesRegex(Block.ChainError, "operations are creating tree inside the block"):
            blocks[5].put()

        blocks[2].extend_operations([operations[6]])
        blocks[2].mine()
        with self.assertRaisesRegex(Block.ChainError, "operation's previous_operation_rev is not pointing at "
                                                      "the last operation on current blockchain"):
            blocks[2].put()

    def tearDown(self):
        close_database()
        os.remove('test_database_file')
