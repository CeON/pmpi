from io import BytesIO
from uuid import UUID
from pmpi.exceptions import RawFormatError
from pmpi.utils import read_bytes, read_uint32, read_string, read_sized_bytes
from pmpi.public_key import PublicKey

import pmpi.abstract
import pmpi.block
import pmpi.core


class OperationRev(pmpi.abstract.AbstractRevision):
    def _get_revision_from_database(self):
        return Operation.get(self._id)


class Operation(pmpi.abstract.AbstractSignedObject):
    """
    :type __previous_operation: OperationRev
    :type __uuid: UUID
    :type __address: str
    :type __owners: tuple[PublicKey]
    """

    VERSION = 1

    __previous_operation = None
    __uuid = None
    __address = None
    __owners = None

    def __init__(self, previous_operation, uuid, address, owners):
        """
        :type owners: tuple[PublicKey] | list[PublicKey]
        """

        self.__previous_operation = previous_operation
        self.__uuid = uuid
        self.__address = address
        self.__owners = tuple(owners)
        self.__containing_blocks = tuple()

    @classmethod
    def from_owners_der(cls, previous_operation, uuid, address, owners_der):
        op = cls(previous_operation, uuid, address, [])
        op.__owners = tuple(PublicKey(der) for der in owners_der)
        return op

    # Getters

    @property
    def previous_operation(self):
        return self.__previous_operation

    @property
    def uuid(self):
        return self.__uuid

    @property
    def address(self):
        return self.__address

    @property
    def owners(self):
        return self.__owners

    @property
    def owners_der(self):
        return tuple(owner.der for owner in self.owners)

    @property
    def owners_verifying_keys(self):
        return tuple(owner.verifying_key for owner in self.owners)

    @property
    def containing_blocks(self):
        return self.__containing_blocks

    def __add_containing_block(self, block_rev):
        if pmpi.block.Block.exist(bytes(block_rev)):
            if self.hash() not in block_rev.revision.operations_hashes:
                raise self.DoesNotExist("block doesn't contain requested operation")

            if bytes(block_rev) not in self.containing_blocks:
                self.__containing_blocks += (bytes(block_rev),)
        else:
            raise pmpi.block.Block.DoesNotExist

    def __remove_containing_block(self, block_rev):
        if pmpi.block.Block.exist(bytes(block_rev)) and block_rev.revision.is_in_database():
            raise pmpi.block.Block.ChainError("block isn't removed from the database")

        if bytes(block_rev) not in self.containing_blocks:
            raise pmpi.block.Block.DoesNotExist("block isn't listed on containing blocks list")

        self.__containing_blocks = tuple(bl for bl in self.containing_blocks if bl != bytes(block_rev))

    # Serialization and deserialization

    def unsigned_raw(self):
        """
        :return: Raw operation without signature data
        :raise self.VerifyError: when self.public_key is None
        """

        ret = self.VERSION.to_bytes(4, 'big')
        ret += bytes(self.previous_operation)
        ret += self.uuid.bytes
        ret += len(self.address).to_bytes(4, 'big')
        ret += bytes(self.address, 'utf-8')
        ret += len(self.owners).to_bytes(4, 'big')
        ret += b''.join([len(owner).to_bytes(4, 'big') + owner for owner in self.owners_der])
        return ret

    def _database_raw(self):
        raw = self.raw()
        ret = len(raw).to_bytes(4, 'big') + raw
        ret += len(self.containing_blocks).to_bytes(4, 'big') + b''.join(self.containing_blocks)
        return ret

    @classmethod
    def _from_raw_without_verifying(cls, raw):
        buffer = BytesIO(raw)

        if read_uint32(buffer) != cls.VERSION:
            raise RawFormatError("version number mismatch")

        previous_revision = OperationRev.from_id(read_bytes(buffer, 32))
        uuid = UUID(bytes=read_bytes(buffer, 16))
        address = read_string(buffer)
        owners_der = tuple(read_sized_bytes(buffer) for _ in range(read_uint32(buffer)))
        public_key_der = read_sized_bytes(buffer)
        signature = read_sized_bytes(buffer)

        if len(buffer.read()) > 0:
            raise RawFormatError("raw input too long")

        if int.from_bytes(previous_revision.id, 'big') == 0:
            previous_revision = OperationRev()

        operation = cls.from_owners_der(previous_revision, uuid, address, owners_der)
        operation.sign(PublicKey(public_key_der), signature)
        return operation

    @classmethod
    def _from_database_raw(cls, raw):
        buffer = BytesIO(raw)
        operation = cls._from_raw_without_verifying(read_sized_bytes(buffer))
        operation.__containing_blocks = tuple(read_bytes(buffer, 32) for _ in range(read_uint32(buffer)))
        return operation

    # Verification

    def verify(self):
        self.verify_signature()

        if len(self.owners_der) != len(set(self.owners_der)):
            raise self.VerifyError("duplicated owners")

        try:
            prev_operation = self.previous_operation.revision
            if prev_operation is not None:
                if self.public_key.der not in prev_operation.owners_der:
                    raise self.OwnershipError

                if self.uuid != prev_operation.uuid:
                    raise self.VerifyError("uuid mismatch")

                # TODO [is it necessary?] check if prev_operation already exist in database!
                # TODO [[ OR ]] should it be moved to put_verify???
            else:
                pass  # TODO MINTING OPERATION -- check if uuid fulfill some requirements

        except self.DoesNotExist:
            raise self.ChainError("previous_revision_id does not exist")

        return True

    def put_verify(self):
        if self.previous_operation.is_none():  # it's a minting operation
            for rev in Operation.get_revision_id_list():
                if rev != self.hash() and Operation.get(rev).uuid == self.uuid:
                    raise self.ChainError("trying to create a minting operation for an existing uuid")

    def remove_verify(self):
        if len(self.containing_blocks) > 0:
            raise self.ChainOperationBlockedError("can't remove: operation is contained by some blocks")

    # Database operations

    @classmethod
    def _get_dbname(cls):
        return pmpi.core.Database.OPERATIONS

    def is_in_database(self):
        if super(Operation, self).is_in_database():
            db_operation = self.get(self.hash())
            return db_operation.containing_blocks == self.containing_blocks
        else:
            return False

    def put(self, block_rev):
        """
        Put the operation as contained by a given block_rev.
        """
        self.__add_containing_block(block_rev)
        super(Operation, self).put()

    def remove(self, block_rev):
        # When the containing_blocks tuple is cleared, we can remove operation. We don't need to check if there are any
        # operations with previous_operation set to the removing one, because no operations like this can exist. We're
        # removing op. only when we can remove block (the last one of containing_blocks), thus there is no other blocks
        # after that -- no other operations. If there was another operation after removing one in the same block -- we
        # will also remove it, because it's contained by only one -- being removed -- block.
        self.__remove_containing_block(block_rev)
        if len(self.containing_blocks) == 0:
            super(Operation, self).remove()
