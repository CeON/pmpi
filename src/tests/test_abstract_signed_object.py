from unittest import TestCase

import pmpi.block  # FIXME without this import everything explodes
import pmpi.abstract


class TestAbstractSignedObject(TestCase):
    def test_not_implemented(self):
        abstract_object = pmpi.abstract.AbstractSignedObject()

        with self.assertRaises(NotImplementedError):
            abstract_object.get_rev()

        with self.assertRaises(NotImplementedError):
            abstract_object.unsigned_raw()

        with self.assertRaises(NotImplementedError):
            abstract_object._from_raw_without_verifying(b"something")

        with self.assertRaises(NotImplementedError):
            abstract_object.verify()

        with self.assertRaises(NotImplementedError):
            abstract_object.put_verify()

        with self.assertRaises(NotImplementedError):
            abstract_object.remove_verify()

        with self.assertRaises(NotImplementedError):
            abstract_object._get_dbname()
