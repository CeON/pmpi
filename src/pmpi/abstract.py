from ecdsa import BadSignatureError
from pmpi.core import database_required
from pmpi.exceptions import ObjectDoesNotExist
from pmpi.utils import double_sha


class AbstractRevision:
    _id = None
    _revision = None

    @classmethod
    def from_id(cls, identifier):
        rev = cls()
        rev._id = identifier
        return rev

    @classmethod
    def from_revision(cls, revision):
        """
        :type revision: AbstractSignedObject
        """
        rev = cls()
        rev._id = revision.hash()
        rev._revision = revision
        return rev

    def __bytes__(self):
        return self._id if self._id is not None else bytes(32)

    def __eq__(self, other):
        return bytes(self) == bytes(other)

    def _get_revision_from_database(self):
        raise NotImplementedError

    @property
    def id(self):
        return self._id

    @property
    def revision(self):
        if self._id is not None and self._revision is None:
            self._revision = self._get_revision_from_database()

        if self._revision is not None:
            return self._revision
        else:
            return None

    def is_none(self):
        return self._id is None and self._revision is None


class AbstractSignedObject:
    """
    :type __public_key: PublicKey
    :type __signature: SigningKey
    """

    __requires_signature_verification = True
    __public_key = None
    __signature = None
    __hash = None

    @property
    def public_key(self):
        return self.__public_key

    @property
    def signature(self):
        return self.__signature

    @property
    def requires_signature_verification(self):
        return self.__requires_signature_verification

    def hash(self):
        if self.requires_signature_verification or self.__hash is None:
            self.__hash = double_sha(self.raw())
        return self.__hash

    def sign(self, public_key, signature):
        self.__public_key = public_key
        self.__signature = signature
        self.__requires_signature_verification = True

    # Serialisation

    def unsigned_raw(self):
        raise NotImplementedError

    def raw(self):
        self.verify_signature()
        ret = self.unsigned_raw()
        ret += len(self.__public_key.der).to_bytes(4, 'big') + self.__public_key.der
        # noinspection PyTypeChecker
        ret += len(self.__signature).to_bytes(4, 'big') + self.__signature
        return ret

    def _database_raw(self):
        return self.raw()

    @classmethod
    def _from_raw_without_verifying(cls, raw):
        raise NotImplementedError

    @classmethod
    def from_raw(cls, raw):
        obj = cls._from_raw_without_verifying(raw)
        obj.verify()
        return obj

    @classmethod
    def _from_database_raw(cls, raw):
        return cls._from_raw_without_verifying(raw)

    # Verification

    def verify_signature(self):
        if self.requires_signature_verification:
            if self.__signature is not None:
                try:
                    self.__public_key.verifying_key.verify(self.__signature, self.unsigned_raw())
                    self.__requires_signature_verification = False
                except BadSignatureError:
                    raise self.VerifyError("wrong signature")
            else:
                raise self.VerifyError("object is not signed")

    def verify_revision_id(self, revision_id):
        if revision_id != self.hash():
            raise self.VerifyError("wrong revision_id")

    def verify(self):
        raise NotImplementedError

    def put_verify(self):
        raise NotImplementedError

    def remove_verify(self):
        raise NotImplementedError

    # Database operations

    @classmethod
    def _get_dbname(cls):
        raise NotImplementedError

    @classmethod
    @database_required
    def get_revision_id_list(cls, database):
        return database.keys(cls._get_dbname())

    @classmethod
    @database_required
    def exist(cls, database, revision_id):
        try:
            database.get(cls._get_dbname(), revision_id)
            return True
        except KeyError:
            return False

    @classmethod
    @database_required
    def get(cls, database, revision_id):
        try:
            obj = cls._from_database_raw(database.get(cls._get_dbname(), revision_id))
            return obj
        except KeyError:
            raise cls.DoesNotExist

    def is_in_database(self):
        try:
            self.get(self.hash())
            return True
        except self.DoesNotExist:
            return False

    @database_required
    def put(self, database):
        self.verify()
        self.put_verify()

        revision_id = self.hash()

        if not self.is_in_database():
            database.put(self._get_dbname(), revision_id, self._database_raw())
        else:
            raise self.DuplicationError("revision_id already in the database")

    @database_required
    def remove(self, database):
        self.remove_verify()

        try:
            database.delete(self._get_dbname(), self.hash())
        except ObjectDoesNotExist:
            raise self.DoesNotExist

    # Exceptions

    class DoesNotExist(ObjectDoesNotExist):
        pass

    class VerifyError(Exception):
        pass

    class ChainError(Exception):
        pass

    class DuplicationError(ChainError):
        pass

    class ChainOperationBlockedError(ChainError):
        pass

    class OwnershipError(Exception):
        pass
