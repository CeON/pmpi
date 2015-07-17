from ecdsa.curves import NIST192p
from ecdsa.keys import SigningKey
from pmpi.utils import sign_object
from pmpi.public_key import PublicKey


class User:
    """

    :type private_key: SigningKey
    """
    def __init__(self, private_key):
        self._private_key = private_key
        self._public_key = PublicKey.from_signing_key(private_key)

    @classmethod
    def new_keys(cls, curve=NIST192p):  # TODO different curve as default?
        """
        Create new user using auto-generated keys.

        :param curve: private key's generation curve
        """
        return cls(SigningKey.generate(curve=curve))

    def sign_operation(self, operation):
        """
        Sign given operation by this user.

        :param operation: operation to sign
        """
        sign_object(self._public_key, self._private_key, operation)
