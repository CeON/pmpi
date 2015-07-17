from unittest import TestCase
from uuid import uuid4
from ecdsa.curves import NIST256p
from ecdsa.keys import SigningKey, VerifyingKey
from pmpi.operation import Operation, OperationRev
from pmpi.user import User
from pmpi.public_key import PublicKey


class TestUser(TestCase):
    def test_init(self):
        sk = SigningKey.generate()
        user = User(sk)

        self.assertEqual(user._private_key, sk)
        self.assertEqual(user._public_key.der, sk.get_verifying_key().to_der())

    def test_new_keys(self):
        user = User.new_keys(curve=NIST256p)

        self.assertIsInstance(user, User)
        self.assertIsInstance(user._private_key, SigningKey)
        self.assertIsInstance(user._public_key.verifying_key, VerifyingKey)

        self.assertEqual(user._private_key.to_der(),
                         SigningKey.from_string(user._private_key.to_string(), NIST256p).to_der())

        self.assertEqual(len(user._private_key.to_der()), len(SigningKey.generate(curve=NIST256p).to_der()))
        self.assertNotEqual(len(user._private_key.to_der()), len(SigningKey.generate().to_der()))

    def test_sign_operation(self):
        op = Operation(OperationRev(), uuid4(), 'http://example.com/',
                       [PublicKey.from_signing_key(SigningKey.generate())])
        user = User.new_keys()

        with self.assertRaisesRegex(Operation.VerifyError, "object is not signed"):
            op.verify()

        user.sign_operation(op)

        self.assertTrue(op.verify())
        self.assertEqual(op.public_key, user._public_key)
