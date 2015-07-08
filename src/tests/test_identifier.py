import hashlib
import os
from unittest import TestCase, mock
from uuid import uuid4

from src.pmpi import Identifier, Operation, RawFormatError
from src.pmpi.core import Database, initialise_database, close_database


def make_mock_operation(some_bytes):
    operation = mock.Mock(Operation)
    operation.sha256 = mock.MagicMock(return_value=hashlib.sha256(some_bytes).digest())
    return operation


class TestIdentifier(TestCase):
    def setUp(self):
        self.operation_mock = make_mock_operation(b'operation')
        self.uuid = uuid4()
        self.identifier = Identifier(self.uuid, 'http://example.com/', [b'first_key', b'second_key'],
                                     self.operation_mock.sha256())

    def test_fields(self):
        self.assertEqual(self.identifier.uuid, self.uuid)
        self.assertEqual(self.identifier.address, 'http://example.com/')
        self.assertEqual(self.identifier.owners, [b'first_key', b'second_key'])
        self.assertEqual(self.identifier.revision_id, self.operation_mock.sha256())
        self.assertEqual(len(self.operation_mock.sha256()), 32)

    def test_raw(self):
        raw = self.identifier.raw()

        self.assertIsInstance(raw, bytes)
        self.assertEqual(raw, self.operation_mock.sha256() +
                         len(self.identifier.address).to_bytes(4, 'big') + bytes(self.identifier.address, 'utf-8') +
                         len(self.identifier.owners).to_bytes(4, 'big') + b''.join(
            [len(owner).to_bytes(4, 'big') + owner for owner in self.identifier.owners]))

    def test_from_raw(self):
        new_identifier = Identifier.from_raw(self.uuid, self.identifier.raw())

        self.assertIsInstance(new_identifier, Identifier)
        for attr in ('uuid', 'address', 'owners', 'revision_id'):
            self.assertEqual(getattr(new_identifier, attr), getattr(self.identifier, attr))

    def test_from_wrong_raw(self):
        with self.assertRaisesRegex(RawFormatError, "raw input too short"):
            Identifier.from_raw(self.uuid, self.identifier.raw()[:-1])  # raw without last byte

        with self.assertRaisesRegex(RawFormatError, "raw input too long"):
            Identifier.from_raw(self.uuid, self.identifier.raw() + b'\x00')  # raw with additional byte

class TestNoDatabase(TestCase):

    #TODO test every method

    def test_no_database(self):
        with self.assertRaisesRegex(Database.InitialisationError, "initialise database first"):
            Identifier.get_uuid_list()

class TestIdentifierDatabase(TestCase):
    def setUp(self):
        self.operation1_mock = make_mock_operation(b'operation1')
        self.operation2_mock = make_mock_operation(b'operation2')

        initialise_database('test_database_file')

        self.identifier1 = Identifier(
            uuid4(), 'http://example.com/first/', [b'first_key'], self.operation1_mock.sha256())
        self.identifier2 = Identifier(
            uuid4(), 'http://example.com/second/', [b'second_key'], self.operation2_mock.sha256())

    def test_0_empty(self):
        self.assertEqual(len(Identifier.get_uuid_list()), 0)

    def test_1_get_from_empty(self):
        with self.assertRaises(Identifier.DoesNotExist):
            Identifier.get(self.identifier1.uuid)

    def test_2_put_remove(self):
        self.identifier1.put()
        self.identifier2.put()

        uuid_list = Identifier.get_uuid_list()

        self.assertEqual(len(uuid_list), 2)
        self.assertCountEqual(uuid_list, [id.uuid for id in [self.identifier1, self.identifier2]])

        for id in [self.identifier1, self.identifier2]:
            new_id = Identifier.get(id.uuid)
            self.assertEqual(new_id.uuid, id.uuid)
            self.assertEqual(new_id.raw(), id.raw())

        self.identifier1.remove()

        with self.assertRaises(Identifier.DoesNotExist):
            self.identifier1.remove()  # already removed identifier

        self.assertCountEqual(Identifier.get_uuid_list(), [self.identifier2.uuid])

        with self.assertRaises(Identifier.DoesNotExist):
            Identifier.get(self.identifier1.uuid)

    def tearDown(self):
        close_database()
        os.remove('test_database_file')
