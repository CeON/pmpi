import os
from unittest.case import TestCase
from uuid import uuid4
from ecdsa.keys import SigningKey
from src.pmpi.core import initialise_database, close_database
from src.pmpi.operation import Operation, OperationRev
from src.pmpi.utils import sign_object


class TestBlockChain(TestCase):
    def setUp(self):
        initialise_database('test_database_file')

        self.private_keys = [SigningKey.generate() for _ in range(3)]
        self.public_keys = [pk.get_verifying_key() for pk in self.private_keys]
        self.uuids = [uuid4() for _ in range(3)]

    def add_operations_step1(self):
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
        sign_object(self.public_keys[0], self.private_keys[0], ops[3])

        ops.append(
            Operation(OperationRev.from_revision(ops[3]), self.uuids[1],
                      'http://example2.com/v3/', [self.public_keys[1]])
        )

        sign_object(self.public_keys[1], self.private_keys[1], ops[4])

        return ops

    def add_operations_step2(self, ops):
        ops.extend([
            Operation(OperationRev(), self.uuids[2],
                      'http://example3.com/', [self.public_keys[1], self.public_keys[2]]),
            Operation(ops[2], self.uuids[0], 'http://example1.com/v3/', [self.public_keys[0], self.public_keys[2]])
        ])

        sign_object(self.public_keys[2], self.private_keys[2], ops[5])
        sign_object(self.public_keys[0], self.private_keys[0], ops[6])

        ops.extend([
            Operation(ops[5], self.uuids[2], 'http://example3.com/v2/', [self.public_keys[2]]),
            Operation(ops[6], self.uuids[0], 'http://example1.com/v4/', [self.public_keys[2]])
        ])

        sign_object(self.public_keys[1], self.private_keys[1], ops[7])
        sign_object(self.public_keys[2], self.private_keys[2], ops[8])

        return ops

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
