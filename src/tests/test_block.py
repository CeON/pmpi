from unittest.case import TestCase
from uuid import uuid4
from ecdsa.keys import SigningKey
import time
from src.pmpi.block import BlockRevID, Block
from src.pmpi.operation import Operation, OperationRevID


class TestSingleBlock(TestCase):
    def setUp(self):
        self.private_key = SigningKey.generate()
        self.public_key = self.private_key.get_verifying_key()
        self.timestamp = int(time.time())

        self.operations = [
            Operation(OperationRevID(), uuid4(), 'http://example1.com/', [self.public_key], self.public_key),
            Operation(OperationRevID(), uuid4(), 'http://example2.com/', [self.public_key], self.public_key)
        ]

        self.block = Block(BlockRevID(), self.timestamp, self.operations)

    def test_fields(self):
        pass

    def test_unsigned_raw(self):
        pass

    def test_raw(self):
        pass

    def test_from_raw(self):
        pass

    def test_verify(self):
        pass

    def test_mangled_raw(self):
        pass
