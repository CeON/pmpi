import os
from unittest.case import TestCase

from src.pmpi.core import Database
from src.pmpi.revision import AbstractRevision


class TestDatabase(TestCase):
    def setUp(self):
        self.db = Database('test_database_file')

    def test_create(self):
        self.assertIsInstance(self.db, Database)

        for dbname in Database.DBNAMES:
            self.assertEqual(self.db.length(dbname), 0)

    def tearDown(self):
        os.remove('test_database_file')


class TestAbstractRevision(TestCase):
    def test_not_implemented(self):
        with self.assertRaises(NotImplementedError):
            AbstractRevision()._get_revision_from_database()
