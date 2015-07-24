from uuid import UUID

from pmpi.core import Database, database_required
from pmpi.exceptions import ObjectDoesNotExist
from pmpi.operation import OperationRev


class Identifier:
    """
    :type uuid: UUID
    :type operation_rev: OperationRev
    """

    def __init__(self, uuid, operation_rev):

        """
        :param uuid:
        :param operation_rev:
        """
        self.uuid = uuid
        self.operation_rev = operation_rev
        self.verify()

    @classmethod
    def from_operation(cls, operation):
        return cls(operation.uuid, OperationRev.from_revision(operation))

    def verify(self):
        if self.uuid != self.operation_rev.obj.uuid:
            raise self.VerifyingError("uuid mismatch")

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
        :type uuid: UUID
        :param database: provided by database_required decorator
        :return: an identifier with requested UUID
        :raise cls.DoesNotExist:
        """
        try:
            return Identifier(uuid, OperationRev.from_id(database.get(Database.IDENTIFIERS, uuid.bytes)))
        except KeyError:
            raise cls.DoesNotExist

    @database_required
    def put(self, database):
        """
        Put the identifier into the database.

        :param database: provided by database_required decorator
        """
        database.put(Database.IDENTIFIERS, self.uuid.bytes, self.operation_rev.id)

    @database_required
    def remove(self, database):
        """
        Remove the identifier from the database.

        :param database: provided by database_required decorator
        :raise self.DoesNotExist: when the identifier is not in the database
        """
        try:
            database.delete(Database.IDENTIFIERS, self.uuid.bytes)
        except ObjectDoesNotExist:
            raise self.DoesNotExist

    # Exceptions

    class DoesNotExist(ObjectDoesNotExist):
        pass

    class VerifyingError(Exception):
        pass
