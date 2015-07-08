from hashlib import sha256
import os
from unittest.case import TestCase
from uuid import uuid4
from ecdsa.curves import NIST256p
from ecdsa.keys import SigningKey
from src.pmpi.core import Database, initialise_database, close_database
from src.pmpi.exceptions import RawFormatError
from src.pmpi.operation import Operation, RevisionID


def sign_operation(private_key, operation):
    operation.signature = private_key.sign_deterministic(operation.unsigned_raw())  # FIXME, hashfunc=sha256)


class TestSingleOperation(TestCase):
    # TODO test owners list (if contains duplicated owners)

    def setUp(self):
        # dummy signature:
        self.private_key = SigningKey.generate(curve=NIST256p)
        self.public_key = self.private_key.get_verifying_key()

        self.uuid = uuid4()
        self.operation = Operation(RevisionID(), self.uuid, 'http://example.com/', [self.public_key],
                                   self.public_key)

        sign_operation(self.private_key, self.operation)

    def test_fields(self):
        self.assertEqual(self.operation.previous_revision_id, RevisionID())
        self.assertEqual(self.operation.uuid, self.uuid)
        self.assertEqual(self.operation.address, 'http://example.com/')
        self.assertEqual(self.operation.owners, [self.public_key])
        self.assertEqual(self.operation.public_key, self.public_key)

    def test_unsigned_raw(self):
        unsigned_raw = self.operation.unsigned_raw()

        self.assertIsInstance(unsigned_raw, bytes)
        self.assertEqual(unsigned_raw,
                         Operation.VERSION.to_bytes(4, 'big') +  # version
                         b'\x00' * 32 +  # previous_revision_ID (here: 0)
                         self.uuid.bytes +  # uuid
                         len(self.operation.address).to_bytes(4, 'big') +  # address length
                         bytes(self.operation.address, 'utf-8') +  # address
                         len(self.operation.owners).to_bytes(4, 'big') +  # owners count
                         b''.join([len(owner).to_bytes(4, 'big') + owner  # owners
                                   for owner in self.operation.owners_der()]) +
                         len(self.public_key.to_der()).to_bytes(4, 'big') + self.public_key.to_der()  # pub_key
                         )

    def test_raw(self):
        raw = self.operation.raw()

        self.assertIsInstance(raw, bytes)
        self.assertEqual(raw,
                         self.operation.unsigned_raw() +
                         len(self.operation.signature).to_bytes(4, 'big') + self.operation.signature)

    def test_from_raw(self):
        new_operation = Operation.from_raw(self.operation.sha256(), self.operation.raw())

        self.assertIsInstance(new_operation, Operation)
        for attr in ('previous_revision_id', 'uuid', 'address', 'signature'):
            self.assertEqual(getattr(new_operation, attr), getattr(self.operation, attr))
        self.assertEqual(new_operation.owners_der(), self.operation.owners_der())
        self.assertEqual(new_operation.public_key.to_der(), self.operation.public_key.to_der())

    def test_verify(self):
        self.assertTrue(self.operation.verify())

    def test_mangled_raw(self):
        raw = self.operation.raw()

        with self.assertRaisesRegex(RawFormatError, "raw input too short"):
            Operation.from_raw(self.operation.sha256(), raw[:-1])
        with self.assertRaisesRegex(RawFormatError, "raw input too long"):
            Operation.from_raw(self.operation.sha256(), raw + b'\x00')

        with self.assertRaisesRegex(Operation.VerifyError, "wrong signature"):
            mangled_raw = bytearray(raw)
            try:
                mangled_raw[-1] += 1
            except ValueError:
                mangled_raw[-1] -= 1

            Operation.from_raw(self.operation.sha256(), mangled_raw).verify()

        with self.assertRaisesRegex(Operation.VerifyError, "wrong revision_id"):
            Operation.from_raw(b'wrong hash', raw).verify()  # wrong hash length

        with self.assertRaisesRegex(Operation.VerifyError, "wrong revision_id"):
            Operation.from_raw(sha256(b'wrong hash').digest(), raw).verify()  # different hash


class TestMultipleOperations(TestCase):
    def setUp(self):
        # dummy signatures:
        self.private_key = [SigningKey.generate(curve=NIST256p) for _ in range(3)]
        self.public_key = [pk.get_verifying_key() for pk in self.private_key]

        self.operation = [
            Operation(RevisionID(), uuid4(), 'http://example.com/', [self.public_key[1], self.public_key[2]],
                      self.public_key[1]), None, None
        ]

    def test_0_operation(self):
        with self.assertRaisesRegex(Operation.VerifyError, "operation is not signed"):
            self.operation[0].raw()  # attempt to call .raw() on unsigned operation

        with self.assertRaisesRegex(Operation.VerifyError, "operation is not signed"):
            self.operation[0].verify()  # attempt to verify operation without signing

        with self.assertRaisesRegex(Operation.VerifyError, "wrong signature"):
            # wrong because of incompatibility between public (self.public_key[1]) and private (self.private_key[0])
            sign_operation(self.private_key[0], self.operation[0])
            self.operation[0].verify()

        sign_operation(self.private_key[1], self.operation[0])
        self.operation[0].verify()

    def test_1_operation(self):
        sign_operation(self.private_key[1], self.operation[0])
        self.operation[1] = Operation(RevisionID.from_operation(self.operation[0]), self.operation[0].uuid,
                                      'http://illegal.example.com/',
                                      [self.public_key[2]],
                                      self.public_key[0])

        with self.assertRaises(Operation.OwnershipError):  # TODO RaisesRegex???
            sign_operation(self.private_key[0], self.operation[1])
            self.operation[1].verify()

        self.operation[1].address = 'http://new.example.com/'
        self.operation[1].public_key = self.public_key[2]
        sign_operation(self.private_key[2], self.operation[1])
        self.operation[1].verify()

    def test_2_operation(self):
        sign_operation(self.private_key[1], self.operation[0])
        self.operation[1] = Operation(RevisionID.from_operation(self.operation[0]), self.operation[0].uuid,
                                      'http://new.example.com/', [self.public_key[2]], self.public_key[2])
        sign_operation(self.private_key[2], self.operation[1])
        self.operation[2] = Operation(RevisionID.from_operation(self.operation[1]), uuid4(), 'http://new2.example.com',
                                      [], self.public_key[2])

        with self.assertRaisesRegex(Operation.VerifyError, "uuid mismatch"):
            sign_operation(self.private_key[2], self.operation[2])
            self.operation[2].verify()

        self.operation[2].uuid = self.operation[0].uuid
        sign_operation(self.private_key[2], self.operation[2])
        self.operation[2].verify()


class TestOperationDatabase(TestCase):
    def setUp(self):
        initialise_database('test_database_file')

        self.private_key = SigningKey.generate()
        public_key = self.private_key.get_verifying_key()

        uuid = uuid4()
        self.operation = [
            Operation(RevisionID(), uuid, 'http://example.com/', [public_key], public_key),
            Operation(RevisionID(), uuid, 'http://example2.com/', [public_key, public_key], public_key),
            Operation(RevisionID(), uuid4(), 'http://example3.com/', [public_key], public_key)
        ]

    def test_0_empty(self):
        self.assertEqual(len(Operation.get_revision_id_list()), 0)

    def test_1_get_from_empty(self):
        with self.assertRaises(Operation.DoesNotExist):
            sign_operation(self.private_key, self.operation[0])
            Operation.get(self.operation[0].sha256())

    def test_2_put(self):
        sign_operation(self.private_key, self.operation[0])
        self.operation[0].put()

        with self.assertRaisesRegex(Operation.ChainError, "revision_id already in database"):
            self.operation[0].put()

        self.operation[1].previous_revision_id = RevisionID.from_operation(self.operation[0])
        sign_operation(self.private_key, self.operation[1])

        self.operation[1].put()

        sign_operation(self.private_key, self.operation[2])
        self.operation[2].put()

        revision_id_list = Operation.get_revision_id_list()

        self.assertEqual(len(revision_id_list), 3)
        self.assertCountEqual(revision_id_list, [op.sha256() for op in self.operation])

    def test_3_get_and_remove(self):
        sign_operation(self.private_key, self.operation[0])
        self.operation[1].previous_revision_id = RevisionID.from_operation(self.operation[0])

        for op in self.operation:
            sign_operation(self.private_key, op)
            op.put()

        for op in self.operation:
            new_op = Operation.get(op.sha256())
            self.assertEqual(new_op.sha256(), op.sha256())

        with self.assertRaisesRegex(Operation.ChainError, "can't remove: blocked by another operation"):
            self.operation[0].remove()

        self.assertCountEqual(Operation.get_revision_id_list(), [op.sha256() for op in self.operation])

        self.operation[1].remove()
        self.operation[0].remove()

        self.assertCountEqual(Operation.get_revision_id_list(), [self.operation[2].sha256()])

        self.operation[2].remove()

        for op in self.operation:
            with self.assertRaises(Operation.DoesNotExist):
                op.remove()

            with self.assertRaises(Operation.DoesNotExist):
                op.remove()

    def tearDown(self):
        close_database()
        os.remove('test_database_file')


# TODO test "NoDatabase"

class TestOperationVerify(TestCase):
    def setUp(self):
        # self.db = Database('test_database_file')
        initialise_database('test_database_file')

        self.private_key = [SigningKey.generate(), SigningKey.generate()]
        self.public_key = [pk.get_verifying_key() for pk in self.private_key]

        uuid = uuid4()

        self.operation = [
            Operation(RevisionID(), uuid, 'http://example.com/', [self.public_key[1]], self.public_key[0]),
            Operation(RevisionID(), uuid, 'http://example2.com/', [self.public_key[0], self.public_key[1]],
                      self.public_key[0]),
            Operation(RevisionID(), uuid4(), 'http://example3.com/', [self.public_key[1]], self.public_key[1])
        ]

    def test_put_operation0(self):
        with self.assertRaisesRegex(Operation.VerifyError, "operation is not signed"):
            self.operation[0].put()

        sign_operation(self.private_key[0], self.operation[0])
        self.operation[0].put()

    def test_put_operation1(self):
        sign_operation(self.private_key[0], self.operation[0])
        sign_operation(self.private_key[0], self.operation[1])

        self.operation[0].put()

        with self.assertRaisesRegex(Operation.ChainError, "trying to create minting operation for exsisting uuid"):
            self.operation[1].put()

        self.operation[1].previous_revision_id = RevisionID.from_operation(self.operation[0])
        sign_operation(self.private_key[0], self.operation[1])

        with self.assertRaises(Operation.OwnershipError):
            self.operation[1].put()

        self.operation[1].public_key = self.public_key[1]
        sign_operation(self.private_key[1], self.operation[1])

        self.operation[1].put()

    def test_put_operation_2(self):
        self.operation[2].previous_revision_id = RevisionID.from_id(sha256(b'wrong hash').digest())  ## FIXME [??]
        sign_operation(self.private_key[1], self.operation[2])

        with self.assertRaisesRegex(Operation.ChainError, "previous_revision_id does not exsist"):
            self.operation[2].put()

        sign_operation(self.private_key[0], self.operation[1])
        self.operation[2].previous_revision_id = RevisionID.from_operation(self.operation[1])
        sign_operation(self.private_key[1], self.operation[2])

        with self.assertRaisesRegex(Operation.VerifyError, "uuid mismatch"):
            self.operation[2].put()

        self.operation[2].previous_revision_id = RevisionID()
        sign_operation(self.private_key[1], self.operation[2])
        self.operation[2].put()

    # TODO can operation be updated?

    def tearDown(self):
        close_database()
        os.remove('test_database_file')
