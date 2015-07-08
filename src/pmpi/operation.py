from src.pmpi.exceptions import ObjectDoesNotExist


class Operation:
    VERSION = 1

    def __init__(self, previous_revision_id, uuid, address, owners, public_key):
        self.previous_revision_id = previous_revision_id
        self.uuid = uuid
        self.address = address
        self.owners = owners
        self.public_key = public_key
        self.signature = None

    def verify(self):
        pass

    def sha256(self):
        pass

    # Serialization and deserialization

    def unsigned_raw(self):
        ret = self.VERSION.to_bytes(4, 'big')
        ret += self.previous_revision_id if self.previous_revision_id is not None else bytes(32)
        ret += self.uuid.bytes
        ret += len(self.address).to_bytes(4, 'big')
        ret += bytes(self.address, 'utf-8')
        ret += len(self.owners).to_bytes(4, 'big')
        ret += b''.join([len(owner).to_bytes(4, 'big') + owner for owner in self.owners])
        ret += len(self.public_key.to_string()).to_bytes(4, 'big')
        ret += self.public_key.to_string()
        return ret

    def raw(self):
        return self.unsigned_raw() + self.signature

    @classmethod
    def from_raw(cls, revision_id, raw):
        pass

    # Database operations

    @classmethod
    def get_revision_id_list(cls, database):
        pass

    @classmethod
    def get(cls, database, revision_id):
        pass

    def put(self, database):
        pass

    def remove(self, database):
        pass

    # Exceptions

    class DoesNotExist(ObjectDoesNotExist):
        pass

    class VerifyError(Exception):
        pass

    class OwnershipError(Exception):
        pass

    class ChainError(Exception):
        pass