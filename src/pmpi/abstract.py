from ecdsa import BadSignatureError
from pmpi.exceptions import ObjectDoesNotExist
from pmpi.utils import double_sha
import pmpi.core


class AbstractRevision:
    __id = None
    __obj = None

    @classmethod
    def from_id(cls, obj_id):
        rev = cls()
        rev.__id = obj_id
        return rev

    @classmethod
    def from_obj(cls, obj):
        """
        :type obj: AbstractSignedObject
        """
        rev = cls()
        rev.__id = obj.id
        rev.__obj = obj
        return rev

    def __eq__(self, other):
        return self.id == other.id

    def _get_obj_from_database(self):
        raise NotImplementedError

    @property
    def id(self):
        return self.__id if self.__id is not None else bytes(32)

    @property
    def obj(self):
        if self.__id is not None and self.__obj is None:
            self.__obj = self._get_obj_from_database()

        return self.__obj

    def is_none(self):
        return self.__id is None and self.__obj is None


class AbstractSignedObject:
    """
    :type __public_key: PublicKey
    :type __signature: SigningKey
    """

    __requires_signature_verification = True
    __public_key = None
    __signature = None
    __id = None

    @property
    def public_key(self):
        return self.__public_key

    @property
    def signature(self):
        return self.__signature

    @property
    def requires_signature_verification(self):
        return self.__requires_signature_verification

    @property
    def id(self):
        if self.requires_signature_verification or self.__id is None:
            self.__id = double_sha(self.raw())
        return self.__id

    def get_rev(self):
        raise NotImplementedError

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

    def verify_id(self, obj_id):
        if obj_id != self.id:
            raise self.VerifyError("wrong object id")

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
    @pmpi.core.with_database
    def get_ids_list(cls, database):
        return database.keys(cls._get_dbname())

    @classmethod
    @pmpi.core.with_database
    def exist(cls, database, obj_id):
        try:
            database.get(cls._get_dbname(), obj_id)
            return True
        except KeyError:
            return False

    @classmethod
    @pmpi.core.with_database
    def get(cls, database, obj_id):
        try:
            obj = cls._from_database_raw(database.get(cls._get_dbname(), obj_id))
            obj.__requires_signature_verification = False
            # TODO is the above line safe? it assumes that data stored in the database is always correctly signed...
            return obj
        except KeyError:
            raise cls.DoesNotExist

    def is_in_database(self):
        try:
            self.get(self.id)
            return True
        except self.DoesNotExist:
            return False

    @pmpi.core.with_database
    def put(self, database):
        self.verify()
        self.put_verify()

        obj_id = self.id

        if not self.is_in_database():
            database.put(self._get_dbname(), obj_id, self._database_raw())
        else:
            raise self.DuplicationError("object id already in the database")

    @pmpi.core.with_database
    def remove(self, database):
        self.remove_verify()

        try:
            database.delete(self._get_dbname(), self.id)
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
