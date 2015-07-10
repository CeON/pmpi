from io import BytesIO
from uuid import UUID
from ecdsa.keys import VerifyingKey

from src.pmpi.core import Database, database_required
from src.pmpi import RawFormatError
from src.pmpi.exceptions import ObjectDoesNotExist
from src.pmpi.operation import OperationRevID
from src.pmpi.utils import read_bytes


class Identifier:
    """
    :type uuid: UUID
    :type address: str
    :type owners: list[VerifyingKey]
    :type operation_rev_id: OperationRevID
    """

    def __init__(self, uuid, address, owners, operation_rev_id):

        self.uuid = uuid
        self.address = address
        self.owners = owners
        self.operation_rev_id = operation_rev_id

    # Serialization and deserialization

    def owners_der(self) -> list:
        return [owner.to_der() for owner in self.owners]

    def raw(self):
        ret = self.operation_rev_id.get_id()
        ret += len(self.address).to_bytes(4, 'big') + bytes(self.address, 'utf-8')
        ret += len(self.owners).to_bytes(4, 'big')
        ret += b''.join([len(owner).to_bytes(4, 'big') + owner for owner in self.owners_der()])
        return ret

    @classmethod
    def from_raw(cls, uuid, raw):
        buffer = BytesIO(raw)

        revision_id = OperationRevID.from_id(read_bytes(buffer, 32))
        address = read_bytes(buffer, int.from_bytes(read_bytes(buffer, 4), 'big')).decode('utf-8')
        owners = [VerifyingKey.from_der(read_bytes(buffer, int.from_bytes(read_bytes(buffer, 4), 'big')))
                  for _ in range(int.from_bytes(read_bytes(buffer, 4), 'big'))]

        if len(buffer.read()) > 0:
            raise RawFormatError("raw input too long")

        return cls(uuid, address, owners, revision_id)

    # Database operations

    @classmethod
    @database_required
    def get_uuid_list(cls, database):
        return [UUID(bytes=uuid) for uuid in database.keys(Database.IDENTIFIERS)]

    @classmethod
    @database_required
    def get(cls, database, uuid):
        try:
            return Identifier.from_raw(uuid, database.get(Database.IDENTIFIERS, uuid.bytes))
        except KeyError:
            raise cls.DoesNotExist

    @database_required
    def put(self, database):
        database.put(Database.IDENTIFIERS, self.uuid.bytes, self.raw())

    @database_required
    def remove(self, database):
        try:
            database.delete(Database.IDENTIFIERS, self.uuid.bytes)
        except ObjectDoesNotExist:
            raise self.DoesNotExist

    # Exceptions

    class DoesNotExist(ObjectDoesNotExist):
        pass
