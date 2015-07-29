import os
from unittest.case import TestCase
from pmpi.abstract import AbstractRevision
from pmpi.core import initialise_database, close_database, get_database
import pmpi.database


class TestDatabase(TestCase):
    def setUp(self):
        self.db = pmpi.database.Database('test_database_file')

    def test_create(self):
        self.assertIsInstance(self.db, pmpi.database.Database)

        for dbname in pmpi.database.Database.DBNAMES:
            self.assertEqual(self.db.length(dbname), 0)

    def tearDown(self):
        os.remove('test_database_file')


class TestInitialiseDatabase(TestCase):
    def test_initialise(self):
        initialise_database('test_database_file')

        with self.assertRaisesRegex(pmpi.database.Database.InitialisationError, "close opened database first"):
            initialise_database('test_database_file2')

        with self.assertRaises(OSError):
            os.remove('test_database_file2')

        close_database()
        initialise_database('test_database_file2')
        close_database()

        with self.assertRaisesRegex(pmpi.database.Database.InitialisationError, "there is no database to close"):
            close_database()

        os.remove('test_database_file')
        os.remove('test_database_file2')

    def test_no_database(self):
        with self.assertRaisesRegex(pmpi.database.Database.InitialisationError, "initialise database first"):
            get_database()


class TestAbstractRevision(TestCase):
    def test_not_implemented(self):
        with self.assertRaises(NotImplementedError):
            AbstractRevision()._get_obj_from_database()
