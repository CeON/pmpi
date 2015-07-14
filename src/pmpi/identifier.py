from io import BytesIO
from uuid import UUID
from ecdsa.keys import VerifyingKey

from src.pmpi.core import Database, database_required
from src.pmpi import RawFormatError
from src.pmpi.exceptions import ObjectDoesNotExist
from src.pmpi.operation import OperationRev
from src.pmpi.utils import read_bytes, read_string, read_sized_bytes, read_uint32


class Identifier:
    """
    :type uuid: UUID
    :type address: str
    :type owners: list[VerifyingKey]
    :type operation_rev_id: OperationRev
    """

    def __init__(self, uuid, address, owners, operation_rev_id):

        """
        :param uuid:
        :param address:
        :param owners:
        :param operation_rev_id:
        """
        self.uuid = uuid
        self.address = address
        self.owners = owners
        self.operation_rev_id = operation_rev_id

    # Serialization and deserialization

    def owners_der(self):
        """
        :rtype : list[bytes]
        :return: List of owners converted to DER format
        """
        return [owner.to_der() for owner in self.owners]

    def raw(self):
        """
        :rtype : bytes
        :return: Raw identifier
        """
        ret = self.operation_rev_id.get_id()
        ret += len(self.address).to_bytes(4, 'big') + bytes(self.address, 'utf-8')
        ret += len(self.owners).to_bytes(4, 'big')
        ret += b''.join([len(owner).to_bytes(4, 'big') + owner for owner in self.owners_der()])
        return ret

    @classmethod
    def from_raw(cls, uuid, raw):
        """
        :param uuid: identifier's uuid
        :param raw: raw data
        :return: Identifier object from given raw data
        :raise RawFormatError: when the raw argument is badly formatted
        """

        buffer = BytesIO(raw)
        revision_id = OperationRev.from_id(read_bytes(buffer, 32))
        address = read_string(buffer)
        owners = [VerifyingKey.from_der(read_sized_bytes(buffer)) for _ in range(read_uint32(buffer))]

        if len(buffer.read()) > 0:
            raise RawFormatError("raw input too long")

        return cls(uuid, address, owners, revision_id)

    # Database operations

    @classmethod
    @database_required
    def get_uuid_list(cls, database):
        """
        :param database: provided by database_required decorator
        :return: List of UUIDs stored in the database
        """
        return [UUID(bytes=uuid) for uuid in database.keys(Database.IDENTIFIERS)]

    @classmethod
    @database_required
    def get(cls, database, uuid):
        """

        :param database: provided by database_required decorator
        :param uuid:
        :return: an identifier with requested UUID
        :raise cls.DoesNotExist:
        """
        try:
            return Identifier.from_raw(uuid, database.get(Database.IDENTIFIERS, uuid.bytes))
        except KeyError:
            raise cls.DoesNotExist

    @database_required
    def put(self, database):
        """
        Put the identifier into the database.

        :param database: provided by database_required decorator
        """
        database.put(Database.IDENTIFIERS, self.uuid.bytes, self.raw())

    @database_required
    def remove(self, database):
        """
        Remove the identifier from the database.

        :param database: provided by database_required decorator
        :raise self.DoesNotExist: when the identifier is not in the databse
        """
        try:
            database.delete(Database.IDENTIFIERS, self.uuid.bytes)
        except ObjectDoesNotExist:
            raise self.DoesNotExist

    # Exceptions

    class DoesNotExist(ObjectDoesNotExist):
        pass
