import os
from unittest.case import TestCase
from uuid import uuid4
from ecdsa.keys import SigningKey
import time
from pmpi.block import Block, BlockRev
from pmpi.core import initialise_database, close_database
from pmpi.operation import Operation, OperationRev
from pmpi.utils import sign_object
from pmpi.public_key import PublicKey


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
            Operation(OperationRev.from_revision(ops[0]), self.uuids[0],
                      'http://example1.com/v2/', [self.public_keys[0]]),
            Operation(OperationRev.from_revision(ops[1]), self.uuids[1],
                      'http://example2.com/v2/', [self.public_keys[1]])
        ])

        sign_object(self.public_keys[0], self.private_keys[0], ops[2])
        sign_object(self.public_keys[1], self.private_keys[1], ops[3])

        ops.append(
            Operation(OperationRev.from_revision(ops[3]), self.uuids[1],
                      'http://example2.com/v3/', [self.public_keys[1]])
        )

        sign_object(self.public_keys[1], self.private_keys[1], ops[4])

        ops.extend([
            Operation(OperationRev(), self.uuids[2],
                      'http://example3.com/', [self.public_keys[1], self.public_keys[2]]),
            Operation(OperationRev.from_revision(ops[2]), self.uuids[0],
                      'http://example1.com/v3/', [self.public_keys[0], self.public_keys[2]])
        ])

        sign_object(self.public_keys[2], self.private_keys[2], ops[5])
        sign_object(self.public_keys[0], self.private_keys[0], ops[6])

        ops.extend([
            Operation(OperationRev.from_revision(ops[5]), self.uuids[2],
                      'http://example3.com/v2/', [self.public_keys[2]]),
            Operation(OperationRev.from_revision(ops[6]), self.uuids[0],
                      'http://example1.com/v4/', [self.public_keys[2]])
        ])

        sign_object(self.public_keys[1], self.private_keys[1], ops[7])
        sign_object(self.public_keys[2], self.private_keys[2], ops[8])

        ops.append(
            Operation(OperationRev.from_revision(ops[7]), self.uuids[2],
                      'http://example3.com/v3/', [self.public_keys[2]])
        )

        sign_object(self.public_keys[2], self.private_keys[2], ops[9])

        return ops

    def add_blocks(self, ops):
        start_time = int(time.time()) - 100
        blocks = [Block.from_operations_list(BlockRev(), start_time, [ops[0], ops[1]])]
        blocks[0].mine()
        sign_object(self.public_keys[0], self.private_keys[0], blocks[0])
        blocks.append(Block.from_operations_list(BlockRev.from_revision(blocks[0]), start_time + 10, [ops[2], ops[6]]))
        blocks[1].mine()
        sign_object(self.public_keys[0], self.private_keys[0], blocks[1])
        blocks.append(Block.from_operations_list(BlockRev.from_revision(blocks[1]), start_time + 20, [ops[3], ops[5]]))
        blocks[2].mine()
        sign_object(self.public_keys[0], self.private_keys[0], blocks[2])
        blocks.append(Block.from_operations_list(BlockRev.from_revision(blocks[2]), start_time + 30, [ops[8], ops[4]]))
        blocks[3].mine()
        sign_object(self.public_keys[0], self.private_keys[0], blocks[3])
        blocks.append(Block.from_operations_list(BlockRev.from_revision(blocks[3]), start_time + 40, [ops[4], ops[7]]))
        blocks[4].mine()
        sign_object(self.public_keys[0], self.private_keys[0], blocks[4])
        blocks.append(Block.from_operations_list(BlockRev.from_revision(blocks[3]), start_time + 50, [ops[7], ops[9]]))
        blocks[5].mine()
        sign_object(self.public_keys[0], self.private_keys[0], blocks[5])
        blocks.append(Block.from_operations_list(BlockRev.from_revision(blocks[4]), start_time + 60, [ops[8], ops[9]]))
        blocks[6].mine()
        sign_object(self.public_keys[0], self.private_keys[0], blocks[6])

        return blocks

    def test_build_blocks(self):
        blocks = self.add_blocks(self.add_operations())

        for block in blocks:
            block.put()

    def test_build_identifiers(self):
        pass

    def test_update_database(self):
        pass

    def test_update_identifier(self):
        pass

    def test_get_operations_chain(self):
        pass

    def tearDown(self):
        close_database()
        os.remove('test_database_file')
