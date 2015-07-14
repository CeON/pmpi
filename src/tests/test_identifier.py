import os
from unittest import TestCase
from uuid import uuid4
from ecdsa.keys import SigningKey

from src.pmpi import Identifier, Operation
from src.pmpi.core import Database, initialise_database, close_database
from src.pmpi.operation import OperationRev
from src.pmpi.utils import sign_object


class TestIdentifier(TestCase):
    def setUp(self):
        self.uuid = uuid4()
        self.private_key = SigningKey.generate()
        self.public_keys = [SigningKey.generate().get_verifying_key(), SigningKey.generate().get_verifying_key()]
        self.operation = Operation(OperationRev(), self.uuid, 'http://example.com', self.public_keys)
        sign_object(self.private_key.get_verifying_key(), self.private_key, self.operation)
        self.identifier = Identifier.from_operation(self.operation)

    def test_fields(self):
        self.assertEqual(self.identifier.uuid, self.uuid)
        self.assertEqual(self.identifier.operation_rev, OperationRev.from_revision(self.operation))

    def test_operation_rev(self):
        self.assertIsInstance(self.identifier.operation_rev, OperationRev)
        self.assertIsInstance(self.identifier.operation_rev.get_revision(), Operation)

        op = self.identifier.operation_rev.get_revision()
        self.assertEqual(op.uuid, self.uuid)
        self.assertEqual(op.address, 'http://example.com')
        self.assertEqual(op.owners, self.public_keys)


class TestNoDatabase(TestCase):
    def test_no_database(self):
        with self.assertRaisesRegex(Database.InitialisationError, "initialise database first"):
            Identifier.get_uuid_list()

        with self.assertRaisesRegex(Database.InitialisationError, "initialise database first"):
            Identifier.get(uuid4())

        operation = Operation(OperationRev(), uuid4(), 'http://example.com/', [])
        sk = SigningKey.generate()
        sign_object(sk.get_verifying_key(), sk, operation)
        identifier = Identifier.from_operation(operation)

        with self.assertRaisesRegex(Database.InitialisationError, "initialise database first"):
            identifier.put()

        with self.assertRaisesRegex(Database.InitialisationError, "initialise database first"):
            identifier.remove()


class TestIdentifierDatabase(TestCase):
    def setUp(self):
        initialise_database('test_database_file')

        self.operations = [
            Operation(OperationRev(), uuid4(), 'http://example.com/' + url, [SigningKey.generate().get_verifying_key()])
            for url in ('first/', 'second/')]

        for op in self.operations:
            sk = SigningKey.generate()
            sign_object(sk.get_verifying_key(), sk, op)
            op.put()

        self.identifiers = [Identifier.from_operation(op) for op in self.operations]

    def test_0_empty(self):
        self.assertEqual(len(Identifier.get_uuid_list()), 0)

    def test_1_get_from_empty(self):
        with self.assertRaises(Identifier.DoesNotExist):
            Identifier.get(self.identifiers[0].uuid)

    def test_2_put_remove(self):
        for identifier in self.identifiers:
            identifier.put()

        uuid_list = Identifier.get_uuid_list()

        self.assertEqual(len(uuid_list), 2)
        self.assertCountEqual(uuid_list, [identifier.uuid for identifier in self.identifiers])

        for identifier in self.identifiers:
            new_id = Identifier.get(identifier.uuid)
            self.assertEqual(new_id.uuid, identifier.uuid)
            self.assertEqual(new_id.operation_rev, identifier.operation_rev)

        self.identifiers[0].remove()

        with self.assertRaises(Identifier.DoesNotExist):
            self.identifiers[0].remove()  # already removed identifier

        self.assertCountEqual(Identifier.get_uuid_list(), [self.identifiers[1].uuid])

        with self.assertRaises(Identifier.DoesNotExist):
            Identifier.get(self.identifiers[0].uuid)

    def tearDown(self):
        close_database()
        os.remove('test_database_file')
