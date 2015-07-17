import os
from unittest.case import TestCase
from pmpi.abstract_revision import AbstractRevision
from pmpi.core import Database, initialise_database, close_database


class TestDatabase(TestCase):
    def setUp(self):
        self.db = Database('test_database_file')

    def test_create(self):
        self.assertIsInstance(self.db, Database)

        for dbname in Database.DBNAMES:
            self.assertEqual(self.db.length(dbname), 0)

    def tearDown(self):
        os.remove('test_database_file')


class TestInitialiseDatabase(TestCase):
    def test_initialise(self):
        initialise_database('test_database_file')

        with self.assertRaisesRegex(Database.InitialisationError, "close opened database first"):
            initialise_database('test_database_file2')

        with self.assertRaises(OSError):
            os.remove('test_database_file2')

        close_database()
        initialise_database('test_database_file2')
        close_database()

        with self.assertRaisesRegex(Database.InitialisationError, "there is no database to close"):
            close_database()

        os.remove('test_database_file')
        os.remove('test_database_file2')


class TestAbstractRevision(TestCase):
    def test_not_implemented(self):
        with self.assertRaises(NotImplementedError):
            AbstractRevision()._get_revision_from_database()
