from io import BytesIO
from uuid import UUID

from ecdsa.keys import VerifyingKey, BadSignatureError

from src.pmpi.core import Database, database_required
from src.pmpi.exceptions import ObjectDoesNotExist, RawFormatError
from src.pmpi.revision import AbstractRevision
from src.pmpi.utils import read_bytes, double_sha, read_uint32, read_string, read_sized_bytes


class OperationRev(AbstractRevision):
    def _get_revision_from_database(self):
        return Operation.get(self._id)


class Operation:
    """
    
    :type previous_operation: OperationRev
    :type uuid: UUID
    :type address: str
    :type owners: list[VerifyingKey]
    :type public_key: NoneType | VerifyingKey
    :type signature: NoneType | bytes
    """

    VERSION = 1

    def __init__(self, previous_operation, uuid, address, owners):
        self.previous_operation = previous_operation
        self.uuid = uuid
        self.address = address
        self.owners = owners
        self.public_key = None
        self.signature = None

    def verify_signature(self):  # todo
        if self.signature is not None:
            try:
                self.public_key.verify(self.signature, self.unsigned_raw())  # FIXME? , hashfunc=sha256)
            except BadSignatureError:
                raise self.VerifyError("wrong signature")
            return True
        else:
            raise self.VerifyError("operation is not signed")

    def verify_revision_id(self, revision_id):
        if revision_id != self.hash():
            raise self.VerifyError("wrong revision_id")

    def verify(self):
        self.verify_signature()

        if len(self.owners_der()) != len(set(self.owners_der())):
            raise self.VerifyError("duplicated owners")

        try:
            prev_operation = self.previous_operation.get_revision()
            if prev_operation is not None:
                if self.public_key.to_der() not in prev_operation.owners_der():
                    raise self.OwnershipError

                if self.uuid != prev_operation.uuid:
                    raise self.VerifyError("uuid mismatch")

                # TODO check if prev_operation already exist in database!

        except self.DoesNotExist:
            raise self.ChainError("previous_revision_id does not exist")

        return True

    def hash(self):
        return double_sha(self.raw())

    # Serialization and deserialization

    def owners_der(self):
        return [owner.to_der() for owner in self.owners]

    def unsigned_raw(self):
        """
        :return: Raw operation without signature data
        :raise self.VerifyError: when self.public_key is None
        """
        if self.public_key is None:
            raise self.VerifyError("operation is not signed")

        ret = self.VERSION.to_bytes(4, 'big')
        ret += bytes(self.previous_operation)
        ret += self.uuid.bytes
        ret += len(self.address).to_bytes(4, 'big')
        ret += bytes(self.address, 'utf-8')
        ret += len(self.owners).to_bytes(4, 'big')
        ret += b''.join([len(owner).to_bytes(4, 'big') + owner for owner in self.owners_der()])
        ret += len(self.public_key.to_der()).to_bytes(4, 'big')
        ret += self.public_key.to_der()
        return ret

    def raw(self):
        """
        :return: Raw operation
        :raise self.VerifyError: when operations isn't correctly signed
        """
        self.verify_signature()
        return self.unsigned_raw() + len(self.signature).to_bytes(4, 'big') + self.signature

    @classmethod
    def from_raw(cls, raw):
        buffer = BytesIO(raw)

        if read_uint32(buffer) != cls.VERSION:
            raise RawFormatError("version number mismatch")

        previous_revision = OperationRev.from_id(read_bytes(buffer, 32))
        uuid = UUID(bytes=read_bytes(buffer, 16))
        address = read_string(buffer)
        owners = [VerifyingKey.from_der(read_sized_bytes(buffer)) for _ in range(read_uint32(buffer))]
        public_key = VerifyingKey.from_der(read_sized_bytes(buffer))
        signature = read_sized_bytes(buffer)

        if len(buffer.read()) > 0:
            raise RawFormatError("raw input too long")

        if int.from_bytes(previous_revision.get_id(), 'big') == 0:
            previous_revision = OperationRev()

        operation = cls(previous_revision, uuid, address, owners)
        operation.public_key = public_key
        operation.signature = signature

        operation.verify()

        return operation

    # Database operations

    @classmethod
    @database_required
    def get_revision_id_list(cls, database):
        return database.keys(Database.OPERATIONS)

    @classmethod
    @database_required
    def get(cls, database, revision_id):
        try:
            operation = Operation.from_raw(database.get(Database.OPERATIONS, revision_id))
            operation.verify_revision_id(revision_id)
            return operation
        except KeyError:
            raise cls.DoesNotExist

    @database_required
    def put(self, database):
        self.verify()
        revision_id = self.hash()

        # FIXME naive algorithm !!!
        for rev in Operation.get_revision_id_list():
            op = Operation.get(rev)
            if rev != revision_id and op.uuid == self.uuid and self.previous_operation.is_none():
                raise self.ChainError("trying to create minting operation for existing uuid")

        try:
            self.get(revision_id)
            raise self.ChainError("revision_id already in database")
        except self.DoesNotExist:
            database.put(Database.OPERATIONS, self.hash(), self.raw())

    @database_required
    def remove(self, database):
        revision_id = self.hash()

        # FIXME naive algorithm !!!
        for rev in Operation.get_revision_id_list():
            op = Operation.get(rev)
            if op.previous_operation.get_id() == revision_id:
                raise self.ChainError("can't remove: blocked by another operation")

        try:
            database.delete(Database.OPERATIONS, revision_id)
        except ObjectDoesNotExist:
            raise self.DoesNotExist

    # Exceptions

    class DoesNotExist(ObjectDoesNotExist):
        pass

    class VerifyError(Exception):
        pass

    class OwnershipError(Exception):
        pass

    class ChainError(Exception):
        pass
