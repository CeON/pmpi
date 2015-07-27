from uuid import UUID
from pmpi.core import with_database
from pmpi.exceptions import ObjectDoesNotExist
import pmpi.database
import pmpi.operation


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
        return cls(operation.uuid, pmpi.operation.OperationRev.from_obj(operation))

    def verify(self):
        if self.uuid != self.operation_rev.obj.uuid:
            raise self.VerifyingError("uuid mismatch")

    # Database operations

    @classmethod
    @with_database
    def get_uuid_list(cls, database):
        """
        :param database: provided by database_required decorator
        :return: List of UUIDs stored in the database
        """
        return [UUID(bytes=uuid) for uuid in database.keys(pmpi.database.Database.IDENTIFIERS)]

    @classmethod
    @with_database
    def get(cls, database, uuid):
        """
        :type uuid: UUID
        :param database: provided by database_required decorator
        :return: an identifier with requested UUID
        :raise cls.DoesNotExist:
        """
        try:
            return Identifier(uuid, pmpi.operation.OperationRev.from_id(
                database.get(pmpi.database.Database.IDENTIFIERS, uuid.bytes)))
        except KeyError:
            raise cls.DoesNotExist

    @with_database
    def put(self, database):
        """
        Put the identifier into the database.

        :param database: provided by database_required decorator
        """
        database.put(pmpi.database.Database.IDENTIFIERS, self.uuid.bytes, self.operation_rev.id)

    @pmpi.core.with_database
    def remove(self, database):
        """
        Remove the identifier from the database.

        :param database: provided by database_required decorator
        :raise self.DoesNotExist: when the identifier is not in the database
        """
        try:
            database.delete(pmpi.database.Database.IDENTIFIERS, self.uuid.bytes)
        except ObjectDoesNotExist:
            raise self.DoesNotExist

    # Exceptions

    class DoesNotExist(ObjectDoesNotExist):
        pass

    class VerifyingError(Exception):
        pass
