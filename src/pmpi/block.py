from src.pmpi.core import database_required
from src.pmpi.exceptions import ObjectDoesNotExist
from src.pmpi.revision_id import AbstractRevisionID
from src.pmpi.utils import double_sha


class BlockRevID(AbstractRevisionID):
    def _get_revision_from_database(self):
        return Block.get(self._id)


class Block:
    VERSION = 1

    def __init__(self, previous_block, timestamp, operations):
        self.previous_block = previous_block
        self.timestamp = timestamp
        self.operations = operations
        self.public_key = None
        self.signature = None

        self.difficulty = 1  # TODO what value shoud be the default, and what does the difficulty mean in particular?
        self.padding = 0
        self.checksum = None

        self.operations_limit = 5  # TODO what value should be the default?

    def counted_checksum(self):
        return double_sha(self.unmined_raw())

    def checksum_correct(self):
        if self.checksum == self.counted_checksum():
            return True
        else:
            raise self.VerifyError("wrong checksum")

    def is_signed(self):
        if self.signature is not None:
            return True
        else:
            raise self.VerifyError("block is not signed")

    def mine(self):  # FIXME method currently for testing purposes
        unmined_raw = self.unmined_raw()
        assert 0 < self.difficulty < 256 # TODO ...
        target = ((1 << 256 - self.difficulty) - 1).to_bytes(32, 'big')

        self.padding = 0

        while double_sha(unmined_raw) > target:
            self.padding += 1
            unmined_raw = unmined_raw[:-4] + self.padding.to_bytes(4, 'big')

        self.checksum = self.counted_checksum()

        # raise NotImplementedError

    def verify(self):  # TODO
        raise NotImplementedError

    def sha256(self):
        return double_sha(self.raw())

    # Serialization and deserialization

    def operations_raw(self):
        return len(self.operations).to_bytes(4, 'big') + b''.join([op.raw() for op in self.operations])

    def unmined_raw(self):
        ret = self.VERSION.to_bytes(4, 'big')
        ret += bytes(self.previous_block)
        ret += self.timestamp.to_bytes(4, 'big')
        ret += self.operations_limit.to_bytes(4, 'big')
        ret += self.operations_raw()
        ret += self.difficulty.to_bytes(4, 'big')
        ret += self.padding.to_bytes(4, 'big')
        return ret

    def unsigned_raw(self):
        if self.checksum_correct():
            return self.unmined_raw() + self.checksum

    def raw(self):
        if self.is_signed():
            ret = self.unsigned_raw()
            ret += len(self.public_key.to_der()).to_bytes(4, 'big') + self.public_key.to_der()
            ret += len(self.signature).to_bytes(4, 'big') + self.signature
            return ret

    @classmethod
    def from_raw(cls, revision_id, raw):  # FIXME
        raise NotImplementedError  # TODO

    # Database operations

    @classmethod
    @database_required
    def get(cls, database, revision_id):
        raise NotImplementedError  # TODO

    @database_required
    def get_blockchain(self, database):
        raise NotImplementedError  # TODO

    @database_required
    def put(self, database):
        raise NotImplementedError  # TODO

    @database_required
    def remove(self, database):
        raise NotImplementedError  # TODO

    # Exceptions

    class DoesNotExist(ObjectDoesNotExist):
        pass

    class VerifyError(Exception):
        pass
