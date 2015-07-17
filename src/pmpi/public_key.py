from ecdsa import VerifyingKey


class PublicKey:
    _der = None
    _verifying_key = None

    def __init__(self, der):
        self._der = der

    @classmethod
    def from_verifying_key(cls, verifying_key):
        """
        :type verifying_key: VerifyingKey
        """
        if verifying_key is None:
            return None
        pk = cls(verifying_key.to_der())
        pk._verifying_key = verifying_key
        return pk

    @classmethod
    def from_signing_key(cls, signing_key):
        """
        :type signing_key: SigningKey
        """
        if signing_key is None:
            return None
        return cls.from_verifying_key(signing_key.get_verifying_key())

    @property
    def der(self):
        return self._der

    @property
    def verifying_key(self):
        if self._verifying_key is None:
            self._verifying_key = VerifyingKey.from_der(self._der)
        return self._verifying_key
