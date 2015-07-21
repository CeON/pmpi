from hashlib import sha256
import os
from unittest.case import TestCase
from uuid import uuid4

from ecdsa.curves import NIST256p
from ecdsa.keys import SigningKey

from pmpi.core import initialise_database, close_database, Database
from pmpi.exceptions import RawFormatError
from pmpi.operation import Operation, OperationRev
from pmpi.utils import sign_object
from pmpi.public_key import PublicKey


class TestSingleOperation(TestCase):
    def setUp(self):
        # dummy signature:
        self.private_key = SigningKey.generate(curve=NIST256p)
        self.public_key = PublicKey.from_signing_key(self.private_key)

        self.uuid = uuid4()
        self.operation = Operation(OperationRev(), self.uuid, 'http://example.com/', [self.public_key])

        sign_object(self.public_key, self.private_key, self.operation)

    def test_fields(self):
        self.assertEqual(self.operation.previous_operation, OperationRev())
        self.assertEqual(self.operation.uuid, self.uuid)
        self.assertEqual(self.operation.address, 'http://example.com/')
        self.assertEqual(self.operation.owners, (self.public_key,))
        self.assertEqual(self.operation.public_key, self.public_key)

    # noinspection PyPropertyAccess
    def test_immutable(self):
        with self.assertRaisesRegex(AttributeError, "can't set attribute"):
            self.operation.previous_operation = OperationRev()
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
        for attr in ('previous_operation', 'uuid', 'address', 'signature'):
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

        with self.assertRaisesRegex(Operation.VerifyError, "wrong revision_id"):
            Operation.from_raw(raw).verify_revision_id(b'wrong hash')  # wrong hash length

        with self.assertRaisesRegex(Operation.VerifyError, "wrong revision_id"):
            Operation.from_raw(raw).verify_revision_id(sha256(b'wrong hash').digest())  # different hash

    def test_owners(self):
        self.operation = Operation(self.operation.previous_operation,
                                   self.operation.uuid,
                                   self.operation.address,
                                   [self.public_key, self.public_key])
        sign_object(self.public_key, self.private_key, self.operation)

        with self.assertRaisesRegex(Operation.VerifyError, "duplicated owners"):
            self.operation.verify()

        self.operation = Operation(self.operation.previous_operation,
                                   self.operation.uuid,
                                   self.operation.address,
                                   [])
        sign_object(self.public_key, self.private_key, self.operation)

        self.assertTrue(self.operation.verify())


class TestMultipleOperations(TestCase):
    def setUp(self):
        # dummy signatures:
        self.private_keys = [SigningKey.generate(curve=NIST256p) for _ in range(3)]
        self.public_keys = [PublicKey.from_signing_key(private_key) for private_key in self.private_keys]

        self.operation = [
            Operation(OperationRev(), uuid4(), 'http://example.com/', [self.public_keys[1], self.public_keys[2]]),
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
        self.operation[1] = Operation(OperationRev.from_revision(self.operation[0]), self.operation[0].uuid,
                                      'http://illegal.example.com/', [self.public_keys[2]])

        with self.assertRaises(Operation.OwnershipError):
            sign_object(self.public_keys[0], self.private_keys[0], self.operation[1])
            self.operation[1].verify()

        self.operation[1] = Operation(OperationRev.from_revision(self.operation[0]), self.operation[0].uuid,
                                      'http://new.example.com/', [self.public_keys[2]])
        sign_object(self.public_keys[2], self.private_keys[2], self.operation[1])

        self.assertTrue(self.operation[1].verify())

    def test_2_operation(self):
        sign_object(self.public_keys[1], self.private_keys[1], self.operation[0])
        self.operation[1] = Operation(OperationRev.from_revision(self.operation[0]), self.operation[0].uuid,
                                      'http://new.example.com/', [self.public_keys[2]])
        sign_object(self.public_keys[2], self.private_keys[2], self.operation[1])
        self.operation[2] = Operation(OperationRev.from_revision(self.operation[1]), uuid4(),
                                      'http://new2.example.com', [])

        with self.assertRaisesRegex(Operation.VerifyError, "uuid mismatch"):
            sign_object(self.public_keys[2], self.private_keys[2], self.operation[2])
            self.operation[2].verify()

        self.operation[2] = Operation(OperationRev.from_revision(self.operation[1]), self.operation[0].uuid,
                                      'http://new2.example.com', [])
        sign_object(self.public_keys[2], self.private_keys[2], self.operation[2])
        self.operation[2].verify()


class TestOperationDatabase(TestCase):
    def setUp(self):
        initialise_database('test_database_file')

        self.private_key = SigningKey.generate()
        self.public_key = PublicKey.from_signing_key(self.private_key)

        uuid = uuid4()
        self.operations = [
            Operation(OperationRev(), uuid, 'http://example.com/', [self.public_key]),
            Operation(OperationRev(), uuid, 'http://example2.com/', [self.public_key]),
            Operation(OperationRev(), uuid4(), 'http://example3.com/', [self.public_key])
        ]

    def test_0_empty(self):
        self.assertEqual(len(Operation.get_revision_id_list()), 0)

    def test_1_get_from_empty(self):
        with self.assertRaises(Operation.DoesNotExist):
            sign_object(self.public_key, self.private_key, self.operations[0])
            Operation.get(self.operations[0].hash())

    def test_2_put(self):
        sign_object(self.public_key, self.private_key, self.operations[0])
        self.operations[0].put()

        with self.assertRaisesRegex(Operation.DuplicatedError, "revision_id already in database"):
            self.operations[0].put()

        self.operations[1] = Operation(OperationRev.from_revision(self.operations[0]),
                                       self.operations[1].uuid,
                                       self.operations[1].address,
                                       self.operations[1].owners)
        sign_object(self.public_key, self.private_key, self.operations[1])

        self.operations[1].put()

        sign_object(self.public_key, self.private_key, self.operations[2])
        self.operations[2].put()

        revision_id_list = Operation.get_revision_id_list()

        self.assertEqual(len(revision_id_list), 3)
        self.assertCountEqual(revision_id_list, [op.hash() for op in self.operations])

    def test_3_get_and_remove(self):
        sign_object(self.public_key, self.private_key, self.operations[0])

        self.operations[1] = Operation(OperationRev.from_revision(self.operations[0]),
                                       self.operations[1].uuid,
                                       self.operations[1].address,
                                       self.operations[1].owners)

        for op in self.operations:
            sign_object(self.public_key, self.private_key, op)
            op.put()

        for op in self.operations:
            new_op = Operation.get(op.hash())
            self.assertEqual(new_op.hash(), op.hash())

        with self.assertRaisesRegex(Operation.ChainOperationBlockedError, "can't remove: blocked by another operation"):
            self.operations[0].remove()

        self.assertCountEqual(Operation.get_revision_id_list(), [op.hash() for op in self.operations])

        self.operations[1].remove()
        self.operations[0].remove()

        self.assertCountEqual(Operation.get_revision_id_list(), [self.operations[2].hash()])

        self.operations[2].remove()

        for op in self.operations:
            with self.assertRaises(Operation.DoesNotExist):
                op.remove()

        self.assertEqual(Operation.get_revision_id_list(), [])

    def tearDown(self):
        close_database()
        os.remove('test_database_file')


class TestNoDatabase(TestCase):
    def test_no_database(self):
        with self.assertRaisesRegex(Database.InitialisationError, "initialise database first"):
            Operation.get_revision_id_list()

        with self.assertRaisesRegex(Database.InitialisationError, "initialise database first"):
            Operation.get(sha256(b'something').digest())

        operation = Operation(OperationRev(), uuid4(), 'http://example.com/', [])
        sk = SigningKey.generate()
        sign_object(PublicKey.from_signing_key(sk), sk, operation)

        with self.assertRaisesRegex(Database.InitialisationError, "initialise database first"):
            operation.put()

        with self.assertRaisesRegex(Database.InitialisationError, "initialise database first"):
            operation.remove()


class TestOperationVerify(TestCase):
    def setUp(self):
        # self.db = Database('test_database_file')
        initialise_database('test_database_file')

        self.private_keys = [SigningKey.generate(), SigningKey.generate()]
        self.public_keys = [PublicKey.from_signing_key(private_key) for private_key in self.private_keys]

        uuid = uuid4()

        self.operation = [
            Operation(OperationRev(), uuid, 'http://example.com/', [self.public_keys[1]]),
            Operation(OperationRev(), uuid, 'http://example2.com/', [self.public_keys[0], self.public_keys[1]]),
            Operation(OperationRev(), uuid4(), 'http://example3.com/', [self.public_keys[1]])
        ]

    def test_put_operation0(self):
        with self.assertRaisesRegex(Operation.VerifyError, "object is not signed"):
            self.operation[0].put()

        sign_object(self.public_keys[0], self.private_keys[0], self.operation[0])
        self.operation[0].put()

    def test_put_operation1(self):
        sign_object(self.public_keys[0], self.private_keys[0], self.operation[0])
        sign_object(self.public_keys[0], self.private_keys[0], self.operation[1])

        self.operation[0].put()

        with self.assertRaisesRegex(Operation.ChainError, "trying to create minting operation for existing uuid"):
            self.operation[1].put()

        self.operation[1] = Operation(OperationRev.from_revision(self.operation[0]),
                                      self.operation[1].uuid,
                                      self.operation[1].address,
                                      self.operation[1].owners)

        sign_object(self.public_keys[0], self.private_keys[0], self.operation[1])

        with self.assertRaises(Operation.OwnershipError):
            self.operation[1].put()

        sign_object(self.public_keys[1], self.private_keys[1], self.operation[1])

        self.operation[1].put()

    def test_put_operation_2(self):
        self.operation[2] = Operation(OperationRev.from_id(sha256(b'wrong hash').digest()),
                                      self.operation[2].uuid,
                                      self.operation[2].address,
                                      self.operation[2].owners)

        sign_object(self.public_keys[1], self.private_keys[1], self.operation[2])

        with self.assertRaisesRegex(Operation.ChainError, "previous_revision_id does not exist"):
            self.operation[2].put()

        sign_object(self.public_keys[0], self.private_keys[0], self.operation[1])

        self.operation[2] = Operation(OperationRev.from_revision(self.operation[1]),
                                      self.operation[2].uuid,
                                      self.operation[2].address,
                                      self.operation[2].owners)

        sign_object(self.public_keys[1], self.private_keys[1], self.operation[2])

        with self.assertRaisesRegex(Operation.VerifyError, "uuid mismatch"):
            self.operation[2].put()

        self.operation[2] = Operation(OperationRev(),
                                      self.operation[2].uuid,
                                      self.operation[2].address,
                                      self.operation[2].owners)

        sign_object(self.public_keys[1], self.private_keys[1], self.operation[2])
        self.operation[2].put()

        # TODO can operation be updated? NOPE.

        with self.assertRaisesRegex(Operation.DuplicatedError, "revision_id already in database"):
            self.operation[2].put()

    def tearDown(self):
        close_database()
        os.remove('test_database_file')
