from unittest.case import TestCase
from uuid import uuid4
from ecdsa.keys import SigningKey
from hashlib import sha256
import time
from src.pmpi.block import BlockRev, Block
from src.pmpi.exceptions import RawFormatError
from src.pmpi.operation import Operation, OperationRev
from src.pmpi.utils import sign_operation


def sign_block(public_key, private_key, block):
    block.public_key = public_key
    block.signature = private_key.sign_deterministic(block.unsigned_raw())


class TestSingleBlock(TestCase):
    def setUp(self):
        self.private_key = SigningKey.generate()
        self.public_key = self.private_key.get_verifying_key()
        self.timestamp = int(time.time())

        self.operations = [
            Operation(OperationRev(), uuid4(), 'http://example1.com/', [self.public_key]),
            Operation(OperationRev(), uuid4(), 'http://example2.com/', [self.public_key])
        ]

        self.block = Block(BlockRev(), self.timestamp, self.operations)

        for op in self.operations:
            sign_operation(self.public_key, self.private_key, op)

        self.block.mine()
        sign_block(self.public_key, self.private_key, self.block)

    def test_fields(self):
        self.assertEqual(self.block.previous_block, BlockRev())
        self.assertEqual(self.block.timestamp, self.timestamp)
        self.assertEqual(self.block.operations, self.operations)
        self.assertEqual(self.block.operations_raw(),
                         len(self.operations).to_bytes(4, 'big') + b''.join(
                             [len(op).to_bytes(4, 'big') + op for op in [op.raw() for op in self.operations]]))

    def test_unmined_raw(self):
        unmined_raw = self.block.unmined_raw()

        self.assertIsInstance(unmined_raw, bytes)
        self.assertEqual(unmined_raw,
                         Block.VERSION.to_bytes(4, 'big') +
                         bytes(BlockRev()) +
                         self.timestamp.to_bytes(4, 'big') +
                         self.block.operations_limit.to_bytes(4, 'big') +
                         self.block.operations_raw() +
                         self.block.difficulty.to_bytes(4, 'big') +
                         self.block.padding.to_bytes(4, 'big')
                         )

    def test_unsigned_raw(self):
        unsigned_raw = self.block.unsigned_raw()

        self.assertIsInstance(unsigned_raw, bytes)
        self.assertEqual(unsigned_raw, self.block.unmined_raw() + self.block.checksum)

    def test_raw(self):
        raw = self.block.raw()

        self.assertIsInstance(raw, bytes)
        self.assertEqual(raw,
                         self.block.unsigned_raw() +
                         len(self.public_key.to_der()).to_bytes(4, 'big') + self.public_key.to_der() +
                         len(self.block.signature).to_bytes(4, 'big') + self.block.signature)

    def test_from_raw(self):
        new_block = Block.from_raw(self.block.hash(), self.block.raw())

        self.assertIsInstance(new_block, Block)
        for attr in ('previous_block', 'timestamp', 'operations_limit', 'difficulty',
                     'padding', 'checksum', 'signature'):
            self.assertEqual(getattr(new_block, attr), getattr(self.block, attr))

        self.assertEqual(new_block.operations_raw(), self.block.operations_raw())
        self.assertEqual(new_block.public_key.to_der(), self.block.public_key.to_der())

    def test_verify(self):
        self.assertTrue(self.block.verify())

    def test_mangled_raw(self):
        raw = self.block.raw()

        with self.assertRaisesRegex(RawFormatError, "raw input too short"):
            Block.from_raw(self.block.hash(), raw[:-1])
        with self.assertRaisesRegex(RawFormatError, "raw input too long"):
            Block.from_raw(self.block.hash(), raw + b'\x00')

        with self.assertRaisesRegex(Block.VerifyError, "wrong signature"):
            mangled_raw = bytearray(raw)
            try:
                mangled_raw[-1] += 1
            except ValueError:
                mangled_raw[-1] -= 1

            Block.from_raw(self.block.hash(), mangled_raw)

        with self.assertRaisesRegex(Block.VerifyError, "wrong revision_id"):
            Block.from_raw(b'wrong hash', raw).verify()

        with self.assertRaisesRegex(Block.VerifyError, "wrong revision_id"):
            Block.from_raw(sha256(b'wrong hash').digest(), raw).verify()

    def test_unsigned_operation(self):
        self.block.operations[0].address = 'http://different.example.com/'

        with self.assertRaisesRegex(Block.VerifyError, "at least one of the operations is not properly signed"):
            self.block.unmined_raw()
