import os
from unittest.case import TestCase

from src.pmpi.core import Database


class TestDatabase(TestCase):
    def setUp(self):
        self.db = Database('test_database_file')

    def test_create(self):
        self.assertIsInstance(self.db, Database)

        for dbname in Database.DBNAMES:
            self.assertEqual(self.db.length(dbname), 0)

    def tearDown(self):
        os.remove('test_database_file')
