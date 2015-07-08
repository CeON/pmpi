from io import BytesIO
from uuid import UUID

from src.pmpi.core import Database
from src.pmpi import RawFormatError
from src.pmpi.exceptions import ObjectDoesNotExist


class Identifier:
    def __init__(self, uuid, address, owners, revision_id):
        self.uuid = uuid
        self.address = address
        self.owners = owners
        self.revision_id = revision_id

    # Serialization and deserialization

    def raw(self):
        ret = self.revision_id
        ret += len(self.address).to_bytes(4, 'big') + bytes(self.address, 'utf-8')
        ret += len(self.owners).to_bytes(4, 'big')
        ret += b''.join([len(owner).to_bytes(4, 'big') + owner for owner in self.owners])
        return ret

    @classmethod
    def from_raw(cls, uuid, raw):
        buffer = BytesIO(raw)

        def read_bytes(size):
            x = buffer.read(size)
            if len(x) != size:
                raise RawFormatError("raw input too short")
            return x

        revision_id = read_bytes(32)
        address = read_bytes(int.from_bytes(read_bytes(4), 'big')).decode('utf-8')
        owners = [read_bytes(int.from_bytes(read_bytes(4), 'big')) for _ in range(int.from_bytes(read_bytes(4), 'big'))]

        if len(buffer.read()) > 0:
            raise RawFormatError("raw input too long")

        return cls(uuid, address, owners, revision_id)

    # Database operations

    @classmethod
    def get_uuid_list(cls, database):
        return [UUID(bytes=uuid) for uuid in database.keys(Database.IDENTIFIERS)]

    @classmethod
    def get(cls, database, uuid):
        try:
            return Identifier.from_raw(uuid, database.get(Database.IDENTIFIERS, uuid.bytes))
        except KeyError:
            raise cls.DoesNotExist

    def put(self, database):
        database.put(Database.IDENTIFIERS, self.uuid.bytes, self.raw())

    def remove(self, database):
        try:
            database.delete(Database.IDENTIFIERS, self.uuid.bytes)
        except ObjectDoesNotExist:
            raise self.DoesNotExist

    # Exceptions

    class DoesNotExist(ObjectDoesNotExist):
        pass
