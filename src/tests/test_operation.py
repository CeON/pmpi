import os
from hashlib import sha256
from unittest.case import TestCase
from uuid import uuid4
from unittest.mock import patch

from ecdsa.curves import NIST256p

from ecdsa.keys import SigningKey

from pmpi.block import BlockRev
from pmpi.core import initialise_database, close_database
import pmpi.database
from pmpi.exceptions import RawFormatError
from pmpi.operation import Operation, OperationRev
from pmpi.utils import sign_object
from pmpi.public_key import PublicKey

patch.object = patch.object


class TestSingleOperation(TestCase):
    def setUp(self):
        self.private_key = SigningKey.generate(curve=NIST256p)
        self.public_key = PublicKey.from_signing_key(self.private_key)

        self.operation = Operation(OperationRev(), 'http://example.com/', [self.public_key])

        sign_object(self.public_key, self.private_key, self.operation)

    def test_fields(self):
        self.assertEqual(self.operation.previous_operation_rev, OperationRev())
        self.assertEqual(self.operation.address, 'http://example.com/')
        self.assertEqual(self.operation.owners, (self.public_key,))
        self.assertEqual(self.operation.public_key, self.public_key)

    # noinspection PyPropertyAccess
    def test_immutable(self):
        with self.assertRaisesRegex(AttributeError, "can't set attribute"):
            self.operation.previous_operation_rev = OperationRev()
        with self.assertRaisesRegex(AttributeError, "can't set attribute"):
            self.operation.uuid = uuid4()
        with self.assertRaisesRegex(AttributeError, "can't set attribute"):
            self.operation.address = 'http://changed.com/'
        with self.assertRaisesRegex(AttributeError, "can't set attribute"):
            self.operation.owners = []

    def test_unsigned_raw(self):
        unsigned_raw = self.operation.unsigned_raw()

        self.assertIsInstance(unsigned_raw, bytes)
        self.assertEqual(unsigned_raw[:36], b'\x00\x00\x00\x01' + b'\x00' * 32)
        self.assertEqual(len(unsigned_raw),
                         4 + 32 + 16 + 4 + len('http://example.com/') + 4 +
                         4 + len(self.public_key.der))

    def test_raw(self):
        raw = self.operation.raw()
        unsigned_raw = self.operation.unsigned_raw()

        self.assertIsInstance(raw, bytes)
        self.assertEqual(raw[:len(unsigned_raw)], self.operation.unsigned_raw())
        self.assertEqual(len(raw), len(unsigned_raw) + 4 + len(self.public_key.der) + 4 + len(self.operation.signature))

    def test_from_raw(self):
        new_operation = Operation.from_raw(self.operation.raw())

        self.assertIsInstance(new_operation, Operation)
        for attr in ('previous_operation_rev', 'uuid', 'address', 'signature'):
            self.assertEqual(getattr(new_operation, attr), getattr(self.operation, attr))
        self.assertEqual(new_operation.owners_der, self.operation.owners_der)
        self.assertEqual(new_operation.public_key.der, self.operation.public_key.der)

    def test_verify(self):
        self.assertTrue(self.operation.verify())

    def test_mangled_raw(self):
        raw = self.operation.raw()

        with self.assertRaisesRegex(RawFormatError, "raw input too short"):
            Operation.from_raw(raw[:-1])
        with self.assertRaisesRegex(RawFormatError, "raw input too long"):
            Operation.from_raw(raw + b'\x00')

        with self.assertRaisesRegex(Operation.VerifyError, "wrong signature"):
            mangled_raw = bytearray(raw)
            mangled_raw[-1] = 0
            Operation.from_raw(mangled_raw).verify()

        with self.assertRaisesRegex(Operation.VerifyError, "wrong object id"):
            Operation.from_raw(raw).verify_id(b'wrong hash')  # wrong hash length

        with self.assertRaisesRegex(Operation.VerifyError, "wrong object id"):
            Operation.from_raw(raw).verify_id(sha256(b'wrong hash').digest())  # different hash

    def test_owners(self):
        self.operation = Operation(self.operation.previous_operation_rev,
                                   self.operation.address,
                                   [self.public_key, self.public_key])
        sign_object(self.public_key, self.private_key, self.operation)

        with self.assertRaisesRegex(Operation.VerifyError, "duplicated owners"):
            self.operation.verify()

        self.operation = Operation(self.operation.previous_operation_rev,
                                   self.operation.address,
                                   [])
        sign_object(self.public_key, self.private_key, self.operation)

        self.assertTrue(self.operation.verify())


class TestMultipleOperations(TestCase):
    def setUp(self):
        self.private_keys = [SigningKey.generate(curve=NIST256p) for _ in range(3)]
        self.public_keys = [PublicKey.from_signing_key(private_key) for private_key in self.private_keys]

        self.operation = [
            Operation(OperationRev(), 'http://example.com/', [self.public_keys[1], self.public_keys[2]]),
            None, None
        ]

    def test_0_operation(self):
        with self.assertRaisesRegex(Operation.VerifyError, "object is not signed"):
            self.operation[0].raw()  # attempt to call .raw() on unsigned operation

        with self.assertRaisesRegex(Operation.VerifyError, "object is not signed"):
            self.operation[0].verify()  # attempt to verify operation without signing

        with self.assertRaisesRegex(Operation.VerifyError, "wrong signature"):
            # wrong because of incompatibility between public (self.public_key[1]) and private (self.private_key[0])
            sign_object(self.public_keys[1], self.private_keys[0], self.operation[0])
            self.operation[0].verify()

        sign_object(self.public_keys[1], self.private_keys[1], self.operation[0])
        self.operation[0].verify()

    def test_1_operation(self):
        sign_object(self.public_keys[0], self.private_keys[0], self.operation[0])
        self.operation[1] = Operation(OperationRev.from_obj(self.operation[0]),
                                      'http://illegal.example.com/', [self.public_keys[2]])

        with self.assertRaises(Operation.OwnershipError):
            sign_object(self.public_keys[0], self.private_keys[0], self.operation[1])
            self.operation[1].verify()

        self.operation[1] = Operation(OperationRev.from_obj(self.operation[0]),
                                      'http://new.example.com/', [self.public_keys[2]])
        sign_object(self.public_keys[2], self.private_keys[2], self.operation[1])

        self.assertTrue(self.operation[1].verify())

    def test_2_operation(self):
        sign_object(self.public_keys[1], self.private_keys[1], self.operation[0])
        self.operation[1] = Operation(OperationRev.from_obj(self.operation[0]),
                                      'http://new.example.com/', [self.public_keys[2]])
        sign_object(self.public_keys[2], self.private_keys[2], self.operation[1])
        self.operation[2] = Operation._construct_with_uuid(OperationRev.from_obj(self.operation[1]), uuid4(),
                                                           'http://new2.example.com', [])

        with self.assertRaisesRegex(Operation.UUIDError, "UUID mismatch"):
            sign_object(self.public_keys[2], self.private_keys[2], self.operation[2])
            self.operation[2].verify()

        self.operation[2] = Operation(OperationRev.from_obj(self.operation[1]), 'http://new2.example.com', [])
        sign_object(self.public_keys[2], self.private_keys[2], self.operation[2])
        self.operation[2].verify()


# noinspection PyArgumentList
@patch.object(Operation, 'put', lambda self: super(Operation, self).put())
@patch.object(Operation, 'remove', lambda self: super(Operation, self).remove())
class TestOperationDatabase(TestCase):
    def setUp(self):

        initialise_database('test_database_file')

        self.private_key = SigningKey.generate()
        self.public_key = PublicKey.from_signing_key(self.private_key)

        self.operations = [
            Operation(OperationRev(), 'http://example.com/', [self.public_key]),
            Operation(OperationRev(), 'http://example2.com/', [self.public_key]),
            Operation(OperationRev(), 'http://example3.com/', [self.public_key])
        ]

    def test_0_empty(self):
        self.assertEqual(len(Operation.get_ids_list()), 0)

    def test_1_get_from_empty(self):
        with self.assertRaises(Operation.DoesNotExist):
            sign_object(self.public_key, self.private_key, self.operations[0])
            Operation.get(self.operations[0].id)

    def test_2_put(self):

        sign_object(self.public_key, self.private_key, self.operations[0])
        self.operations[0].put()

        with self.assertRaisesRegex(Operation.DuplicationError, "object id already in the database"):
            self.operations[0].put()

        self.operations[1] = Operation(OperationRev.from_obj(self.operations[0]),
                                       self.operations[1].address,
                                       self.operations[1].owners)
        sign_object(self.public_key, self.private_key, self.operations[1])

        self.operations[1].put()

        sign_object(self.public_key, self.private_key, self.operations[2])
        self.operations[2].put()

        revision_id_list = Operation.get_ids_list()

        self.assertEqual(len(revision_id_list), 3)
        self.assertCountEqual(revision_id_list, [op.id for op in self.operations])

    def test_3_get_and_remove(self):
        sign_object(self.public_key, self.private_key, self.operations[0])

        self.operations[1] = Operation(OperationRev.from_obj(self.operations[0]),
                                       self.operations[1].address,
                                       self.operations[1].owners)

        for op in self.operations:
            sign_object(self.public_key, self.private_key, op)
            op.put()

        for op in self.operations:
            new_op = Operation.get(op.id)
            self.assertEqual(new_op.id, op.id)

        self.assertCountEqual(Operation.get_ids_list(), [op.id for op in self.operations])

        self.operations[1].remove()
        self.operations[0].remove()

        self.assertCountEqual(Operation.get_ids_list(), [self.operations[2].id])

        self.operations[2].remove()

        for op in self.operations:
            with self.assertRaises(Operation.DoesNotExist):
                op.remove()

        self.assertEqual(Operation.get_ids_list(), [])

    def tearDown(self):
        close_database()
        os.remove('test_database_file')


class TestNoDatabase(TestCase):
    def test_no_database(self):
        with self.assertRaisesRegex(pmpi.database.Database.InitialisationError, "initialise database first"):
            Operation.get_ids_list()

        with self.assertRaisesRegex(pmpi.database.Database.InitialisationError, "initialise database first"):
            Operation.get(sha256(b'something').digest())

        operation = Operation(OperationRev(), 'http://example.com/', [])
        sk = SigningKey.generate()
        sign_object(PublicKey.from_signing_key(sk), sk, operation)

        with self.assertRaisesRegex(pmpi.database.Database.InitialisationError, "initialise database first"):
            operation.put(BlockRev())

        with self.assertRaisesRegex(pmpi.database.Database.InitialisationError, "initialise database first"):
            operation.remove(BlockRev())


# noinspection PyArgumentList
@patch.object(Operation, 'put', lambda self: super(Operation, self).put())
@patch.object(Operation, 'remove', lambda self: super(Operation, self).remove())
class TestOperationVerify(TestCase):
    def setUp(self):
        initialise_database('test_database_file')

        self.private_keys = [SigningKey.generate(), SigningKey.generate()]
        self.public_keys = [PublicKey.from_signing_key(private_key) for private_key in self.private_keys]

        self.operation = [
            Operation(OperationRev(), 'http://example.com/', [self.public_keys[1]]),
            Operation(OperationRev(), 'http://example2.com/', [self.public_keys[0], self.public_keys[1]]),
            Operation(OperationRev(), 'http://example3.com/', [self.public_keys[1]])
        ]

    def test_put_operation0(self):
        with self.assertRaisesRegex(Operation.VerifyError, "object is not signed"):
            self.operation[0].put()

        sign_object(self.public_keys[0], self.private_keys[0], self.operation[0])
        self.operation[0].put()

    def test_put_operation0_and_copy(self):
        sign_object(self.public_keys[0], self.private_keys[0], self.operation[0])
        self.operation[0].put()

        copied_op = Operation(self.operation[0].previous_operation_rev,
                              self.operation[0].address,
                              self.operation[0].owners)
        sign_object(self.public_keys[1], self.private_keys[1], copied_op)

        with self.assertRaisesRegex(Operation.VerifyError, "trying to create a minting operation for an existing uuid"):
            copied_op.put()

    def test_put_operation1(self):
        sign_object(self.public_keys[0], self.private_keys[0], self.operation[0])
        self.operation[0].put()

        self.operation[1] = Operation._construct_with_uuid(OperationRev(),
                                                           self.operation[0].uuid,
                                                           self.operation[1].address,
                                                           self.operation[1].owners)
        sign_object(self.public_keys[0], self.private_keys[0], self.operation[1])

        with self.assertRaisesRegex(Operation.UUIDError,
                                    "UUID of the minting operation does not fulfill the requirements"):
            self.operation[1].put()

        self.operation[1] = Operation(OperationRev.from_obj(self.operation[0]),
                                      self.operation[1].address,
                                      self.operation[1].owners)

        sign_object(self.public_keys[0], self.private_keys[0], self.operation[1])

        with self.assertRaises(Operation.OwnershipError):
            self.operation[1].put()

        sign_object(self.public_keys[1], self.private_keys[1], self.operation[1])

        self.operation[1].put()

    def test_put_operation_2(self):
        with self.assertRaisesRegex(Operation.ChainError, "previous_operation_rev does not exist"):
            self.operation[2] = Operation(OperationRev.from_id(
                sha256(b'wrong hash').digest()), self.operation[2].address, self.operation[2].owners)

        sign_object(self.public_keys[0], self.private_keys[0], self.operation[1])

        self.operation[2] = Operation._construct_with_uuid(OperationRev.from_obj(self.operation[1]),
                                                           self.operation[2].uuid,
                                                           self.operation[2].address,
                                                           self.operation[2].owners)

        sign_object(self.public_keys[1], self.private_keys[1], self.operation[2])

        with self.assertRaisesRegex(Operation.UUIDError, "UUID mismatch"):
            self.operation[2].put()

        self.operation[2] = Operation._construct_with_uuid(OperationRev(),
                                                           self.operation[2].uuid,
                                                           self.operation[2].address,
                                                           self.operation[2].owners)

        sign_object(self.public_keys[1], self.private_keys[1], self.operation[2])
        self.operation[2].put()

        with self.assertRaisesRegex(Operation.DuplicationError, "object id already in the database"):
            self.operation[2].put()

    def tearDown(self):
        close_database()
        os.remove('test_database_file')
