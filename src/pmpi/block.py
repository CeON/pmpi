from src.pmpi.core import database_required
from src.pmpi.exceptions import ObjectDoesNotExist
from src.pmpi.revision_id import AbstractRevisionID


class BlockRevID(AbstractRevisionID):
    def _get_revision_from_database(self):
        return Block.get(self._id)


class Block:
    def __init__(self, previous_block, timestamp, operations):  # FIXME
        pass  # TODO

    def verify(self):  # TODO
        pass  # TODO

    # Serialization and deserialization

    def raw(self):
        pass  # TODO

    @classmethod
    def from_raw(cls):  # FIXME
        pass  # TODO

    # Database operations

    @classmethod
    @database_required
    def get(cls, database, revision_id):
        pass  # TODO

    @database_required
    def get_blockchain(self, database):
        pass  # TODO

    @database_required
    def put(self, database):
        pass  # TODO

    @database_required
    def remove(self, database):
        pass  # TODO

    # Exceptions

    class DoesNotExist(ObjectDoesNotExist):
        pass
