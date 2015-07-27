import os
from unittest.case import TestCase
from uuid import uuid4
from hashlib import sha256
import time

from ecdsa.keys import SigningKey

from pmpi.block import BlockRev, Block
from pmpi.core import close_database, initialise_database
import pmpi.database
from pmpi.exceptions import RawFormatError
from pmpi.operation import Operation, OperationRev
from pmpi.utils import sign_object, double_sha
from pmpi.public_key import PublicKey


class TestSingleBlock(TestCase):
    def setUp(self):
        self.private_key = SigningKey.generate()
        self.public_key = PublicKey.from_signing_key(self.private_key)
        self.timestamp = int(time.time())

        self.operations = (
            Operation(OperationRev(), uuid4(), 'http://example1.com/', [self.public_key]),
            Operation(OperationRev(), uuid4(), 'http://example2.com/', [self.public_key])
        )

        for op in self.operations:
            sign_object(self.public_key, self.private_key, op)

        self.block = Block.from_operations_list(BlockRev(), self.timestamp, self.operations)

        self.block.mine()
        sign_object(self.public_key, self.private_key, self.block)

    def test_fields(self):
        self.assertEqual(self.block.previous_block_rev, BlockRev())
        self.assertEqual(self.block.timestamp, self.timestamp)
        self.assertEqual(self.block.operations, self.operations)
        self.assertEqual(self.block.operations_full_raw(),
                         len(self.operations).to_bytes(4, 'big') + b''.join(
                             [len(op).to_bytes(4, 'big') + op for op in [op.raw() for op in self.operations]]))

    def test_unmined_raw(self):
        unmined_raw = self.block.unmined_raw()

        self.assertIsInstance(unmined_raw, bytes)
        self.assertEqual(unmined_raw[:36], b'\x00\x00\x00\x01' + b'\x00' * 32)
        self.assertEqual(len(unmined_raw), 4 + 32 + 4 + 4 + 4 + 32 * len(self.block.operations) + 4 + 4)

    def test_unsigned_raw(self):
        unsigned_raw = self.block.unsigned_raw()

        self.assertIsInstance(unsigned_raw, bytes)
        self.assertEqual(unsigned_raw[:-32], self.block.unmined_raw())

    def test_raw(self):
        raw = self.block.raw()

        self.assertIsInstance(raw, bytes)
        self.assertEqual(raw,
                         self.block.unsigned_raw() +
                         len(self.public_key.der).to_bytes(4, 'big') + self.public_key.der +
                         len(self.block.signature).to_bytes(4, 'big') + self.block.signature)

    def test_from_raw(self):
        new_block = Block.from_raw_with_operations(self.block.raw_with_operations())

        self.assertIsInstance(new_block, Block)
        for attr in ('previous_block_rev', 'timestamp', 'operations_limit', 'difficulty',
                     'padding', 'signature'):
            self.assertEqual(getattr(new_block, attr), getattr(self.block, attr))

        self.assertEqual(new_block.operations_full_raw(), self.block.operations_full_raw())
        self.assertEqual(new_block.public_key.der, self.block.public_key.der)
        self.assertEqual(new_block.is_checksum_correct(), self.block.is_checksum_correct())

    def test_verify(self):
        self.assertTrue(self.block.verify())

    def test_mangled_raw(self):
        raw = self.block.raw_with_operations()

        with self.assertRaisesRegex(RawFormatError, "raw input too short"):
            Block.from_raw_with_operations(raw[:-1])
        with self.assertRaisesRegex(RawFormatError, "raw input too long"):
            Block.from_raw_with_operations(raw + b'\x00')

        with self.assertRaisesRegex(Block.VerifyError, "wrong signature"):
            mangled_raw = bytearray(raw)
            mangled_raw[-1] = 0
            Block.from_raw_with_operations(mangled_raw).verify_id(self.block.id)

        with self.assertRaisesRegex(Block.VerifyError, "wrong object id"):
            Block.from_raw_with_operations(raw).verify_id(b'wrong hash')

        with self.assertRaisesRegex(Block.VerifyError, "wrong object id"):
            Block.from_raw_with_operations(raw).verify_id(sha256(b'wrong hash'))

    def test_unsigned_operation(self):
        with self.assertRaisesRegex(Block.VerifyError, "at least one of the operations is not properly signed"):
            self.block = Block.from_operations_list(self.block.previous_block_rev, self.block.timestamp, (
                Operation(self.block.operations[0].previous_operation_rev, self.block.operations[0].uuid,
                          'http://different.example.com/', self.block.operations[0].owners),
                self.block.operations[1]
            ))

    def test_wrong_checksum(self):
        self.block._Block__checksum = double_sha(b'something')
        with self.assertRaisesRegex(Block.VerifyError, "wrong checksum"):
            self.block.unsigned_raw()

    def test_block_not_signed(self):
        block = Block.from_operations_list(BlockRev(), int(time.time()), self.operations)
        with self.assertRaisesRegex(Block.VerifyError, "object is not signed"):
            block.verify()


class TestOperationsLimits(TestCase):
    def setUp(self):
        self.private_key = SigningKey.generate()
        self.public_key = PublicKey.from_signing_key(self.private_key)

        self.operations = [Operation(OperationRev(), uuid4(),
                                     'http://example.com/', [self.public_key]) for _ in range(Block.MIN_OPERATIONS + 1)]
        for op in self.operations:
            sign_object(self.public_key, self.private_key, op)

    def test_too_little(self):
        block = Block.from_operations_list(BlockRev(), int(time.time()), self.operations[:Block.MIN_OPERATIONS - 1])
        block.mine()
        sign_object(self.public_key, self.private_key, block)
        with self.assertRaisesRegex(Block.VerifyError, "number of operations doesn't satisfy limitations"):
            block.verify()

    def test_too_much(self):
        block = Block.from_operations_list(BlockRev(), int(time.time()), self.operations)
        block.operations_limit = Block.MIN_OPERATIONS
        block.mine()
        sign_object(self.public_key, self.private_key, block)
        with self.assertRaisesRegex(Block.VerifyError, "number of operations doesn't satisfy limitations"):
            block.verify()

    def test_wrong_limit(self):
        block = Block.from_operations_list(BlockRev(), int(time.time()), self.operations)
        block.operations_limit = Block.MAX_OPERATIONS + 1
        block.mine()
        sign_object(self.public_key, self.private_key, block)
        with self.assertRaisesRegex(Block.VerifyError, "operations_limit out of range"):
            block.verify()


class TestBlockNoDatabase(TestCase):
    def test_no_database(self):
        with self.assertRaisesRegex(pmpi.database.Database.InitialisationError, "initialise database first"):
            Block.get_ids_list()

        with self.assertRaisesRegex(pmpi.database.Database.InitialisationError, "initialise database first"):
            Block.get(sha256(b'something').digest())

        private_key = SigningKey.generate()
        public_key = PublicKey.from_signing_key(private_key)

        operations = [
            Operation(OperationRev(), uuid4(), 'http://example0.com/', [public_key]),
            Operation(OperationRev(), uuid4(), 'http://example1.com/', [public_key])
        ]

        for op in operations:
            sign_object(public_key, private_key, op)

        block = Block.from_operations_list(BlockRev(), int(time.time()), operations)
        block.mine()
        sign_object(public_key, private_key, block)

        with self.assertRaisesRegex(pmpi.database.Database.InitialisationError, "initialise database first"):
            block.put()

        with self.assertRaisesRegex(pmpi.database.Database.InitialisationError, "initialise database first"):
            block.remove()


class TestBlockDatabase(TestCase):
    def setUp(self):
        initialise_database('test_database_file')

        self.private_key = SigningKey.generate()
        self.public_key = PublicKey.from_signing_key(self.private_key)
        self.uuids = [uuid4() for _ in range(3)]

        self.operations = [[
            Operation(OperationRev(),
                      self.uuids[0], 'http://example0.com/v0/', [self.public_key]),
            Operation(OperationRev(),
                      self.uuids[1], 'http://example1.com/v0/', [self.public_key])
        ]]

        for op in self.operations[0]:
            sign_object(self.public_key, self.private_key, op)

        self.operations.append([
            Operation(OperationRev.from_obj(self.operations[0][0]),
                      self.uuids[0], 'http://example0.com/v1/', [self.public_key]),
            Operation(OperationRev.from_obj(self.operations[0][1]),
                      self.uuids[1], 'http://example1.com/v1/', [self.public_key]),
            Operation(OperationRev(),
                      self.uuids[2], 'http://example2.com/v0/', [self.public_key])
        ])

        for op in self.operations[1]:
            sign_object(self.public_key, self.private_key, op)

        self.operations.append([
            Operation(OperationRev.from_obj(self.operations[1][0]),
                      self.uuids[0], 'http://example0.com/v2/', [self.public_key]),
            Operation(OperationRev.from_obj(self.operations[1][1]),
                      self.uuids[1], 'http://example1.com/v2/', [self.public_key])
        ])

        for op in self.operations[2]:
            sign_object(self.public_key, self.private_key, op)

        self.operations.append([
            Operation(OperationRev.from_obj(self.operations[1][1]),
                      self.uuids[1], 'http://alternative1.com/', [self.public_key]),
            Operation(OperationRev.from_obj(self.operations[1][2]),
                      self.uuids[2], 'http://alternative2.com/', [self.public_key])
        ])

        for op in self.operations[3]:
            sign_object(self.public_key, self.private_key, op)

        timestamp = int(time.time()) - 100

        self.blocks = [Block.from_operations_list(BlockRev(), timestamp, self.operations[0])]
        self.blocks[0].mine()
        sign_object(self.public_key, self.private_key, self.blocks[0])
        self.blocks.append(
            Block.from_operations_list(BlockRev.from_obj(self.blocks[0]), timestamp + 20, self.operations[1]))
        self.blocks[1].mine()
        sign_object(self.public_key, self.private_key, self.blocks[1])
        self.blocks.append(
            Block.from_operations_list(BlockRev.from_obj(self.blocks[1]), timestamp + 40, self.operations[2]))
        self.blocks[2].mine()
        sign_object(self.public_key, self.private_key, self.blocks[2])
        self.blocks.append(
            Block.from_operations_list(BlockRev.from_obj(self.blocks[1]), timestamp + 60, self.operations[3]))
        self.blocks[3].mine()
        sign_object(self.public_key, self.private_key, self.blocks[3])

    def test_0_empty(self):
        self.assertEqual(len(Block.get_ids_list()), 0)

    def test_1_get_from_empty(self):
        with self.assertRaises(Block.DoesNotExist):
            Block.get(self.blocks[0].id)

    def test_2_put(self):
        self.blocks[0].put()

        with self.assertRaisesRegex(Block.GenesisBlockDuplication, "trying to create multiple genesis blocks"):
            self.blocks[0].put()

        self.blocks[1].put()

        with self.assertRaisesRegex(Block.DuplicationError, "object id already in the database"):
            self.blocks[1].put()

        self.blocks[2].put()
        self.blocks[3].put()

        revision_id_list = Block.get_ids_list()

        self.assertEqual(len(revision_id_list), 4)
        self.assertCountEqual(revision_id_list, [block.id for block in self.blocks])

    def test_3_get_and_remove(self):
        for block in self.blocks:
            block.put()

        for block in self.blocks:
            new_block = Block.get(block.id)
            self.assertEqual(new_block.id, block.id)

        for block in self.blocks[:2]:
            with self.assertRaisesRegex(Block.ChainOperationBlockedError, "can't remove: blocked by another block"):
                block.remove()

        self.assertCountEqual(Block.get_ids_list(), [block.id for block in self.blocks])

        self.blocks[2].remove()

        for block in self.blocks[:2]:
            with self.assertRaisesRegex(Block.ChainOperationBlockedError, "can't remove: blocked by another block"):
                block.remove()

        self.blocks[3].remove()

        self.assertCountEqual(Block.get_ids_list(), [block.id for block in self.blocks[:2]])

        with self.assertRaisesRegex(Block.ChainOperationBlockedError, "can't remove: blocked by another block"):
            self.blocks[0].remove()

        self.blocks[1].remove()
        self.blocks[0].remove()

        for block in self.blocks:
            with self.assertRaises(Block.DoesNotExist):
                block.remove()

        self.assertEqual(Block.get_ids_list(), [])

    def test_4_wrong_previous_block(self):
        self.blocks[0].previous_block_rev = BlockRev.from_id(double_sha(b'something'))
        self.blocks[0].mine()
        sign_object(self.public_key, self.private_key, self.blocks[0])

        with self.assertRaisesRegex(Block.ChainError, "previous_block_rev does not exist"):
            self.blocks[0].verify()

    def tearDown(self):
        close_database()
        os.remove('test_database_file')
