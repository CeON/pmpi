from io import BytesIO
from uuid import UUID, uuid5
import pmpi.database
from pmpi.exceptions import RawFormatError
from pmpi.utils import read_bytes, read_uint32, read_string, read_sized_bytes
from pmpi.public_key import PublicKey

import pmpi.abstract
import pmpi.block
import pmpi.core


class OperationRev(pmpi.abstract.AbstractRevision):
    def _get_obj_from_database(self):
        return Operation.get(self.id)


class Operation(pmpi.abstract.AbstractSignedObject):
    """
    :type __previous_operation_rev: OperationRev
    :type __uuid: UUID
    :type __address: str
    :type __owners: tuple[PublicKey]
    """

    VERSION = 1
    PMPI_UUID = UUID('b230748e-bcee-4c3b-ba6a-5a25485b5de5')

    __previous_operation_rev = None
    __uuid = None
    __address = None
    __owners = None

    def __init__(self, previous_operation_rev, uuid, address, owners):
        """
        :type owners: tuple[PublicKey] | list[PublicKey]
        """

        self.__previous_operation_rev = previous_operation_rev
        self.__uuid = uuid
        self.__address = address
        self.__owners = tuple(owners)

        self.__containing_blocks = tuple()
        # self.__uuid = self.generate_uuid()

    @classmethod
    def from_owners_der(cls, previous_operation_rev, uuid, address, owners_der):
        op = cls(previous_operation_rev, uuid, address, [])
        op.__owners = tuple(PublicKey(der) for der in owners_der)
        return op

    # Getters

    @property
    def previous_operation_rev(self):
        return self.__previous_operation_rev

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
        if pmpi.block.Block.exist(block_rev.id):
            if self.id not in block_rev.obj.operations_ids:
                raise self.DoesNotExist("block doesn't contain requested operation")

            if block_rev.id not in self.containing_blocks:
                self.__containing_blocks += (block_rev.id,)
        else:
            raise pmpi.block.Block.DoesNotExist

    def __remove_containing_block(self, block_rev):
        if pmpi.block.Block.exist(block_rev.id) and block_rev.obj.is_in_database():
            raise pmpi.block.Block.ChainError("block isn't removed from the database")

        if block_rev.id not in self.containing_blocks:
            raise pmpi.block.Block.DoesNotExist("block isn't listed on containing blocks list")

        self.__containing_blocks = tuple(bl for bl in self.containing_blocks if bl != block_rev.id)

    def generate_uuid(self):
        return uuid5(self.PMPI_UUID, self.address + ''.join(self.owners_der))

    def backward_operations_chain(self, end_operation_id=OperationRev().id):
        root = OperationRev().id
        op = self
        chain = [op.id]
        while op.id != root and op.id != end_operation_id:
            prev_op_rev = op.previous_operation_rev
            op = prev_op_rev.obj
            chain.append(op.id)

        if op.id != end_operation_id:
            raise self.ChainError("end_operation_id is not an ancestor of this operation")

        return chain

    def forward_operations_chain(self, block_id):
        return pmpi.core.get_database().blockchain.forward_operations_chain(self.get_rev(), block_id)

    def get_rev(self):
        return OperationRev.from_obj(self)

    # Serialization and deserialization

    def unsigned_raw(self):
        """
        :return: Raw operation without signature data
        :raise self.VerifyError: when self.public_key is None
        """

        ret = self.VERSION.to_bytes(4, 'big')
        ret += self.previous_operation_rev.id
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
            prev_operation = self.previous_operation_rev.obj
            if prev_operation is not None:
                if self.public_key.der not in prev_operation.owners_der:
                    raise self.OwnershipError

                if self.uuid != prev_operation.uuid:
                    raise self.VerifyError("uuid mismatch")

                # TODO [is it necessary?] check if prev_operation already exist in database!
                # TODO [[ OR ]] should it be moved to put_verify???
            else:
                pass
                # TODO MINTING OPERATION -- check if uuid fulfill some requirements
                # if self.uuid != self.generate_uuid():
                #     raise self.UUIDError("UUID does not fulfill requirements")

        except self.DoesNotExist:
            raise self.ChainError("previous_operation_rev does not exist")

        return True

    def put_verify(self):
        if self.previous_operation_rev.is_none():  # it's a minting operation
            for rev in Operation.get_ids_list():
                if rev != self.id and Operation.get(rev).uuid == self.uuid:
                    raise self.ChainError("trying to create a minting operation for an existing uuid")

    def remove_verify(self):
        if len(self.containing_blocks) > 0:
            raise self.ChainOperationBlockedError("can't remove: operation is contained by some blocks")

    # Database operations

    @classmethod
    def _get_dbname(cls):
        return pmpi.database.Database.OPERATIONS

    def is_in_database(self):
        if super(Operation, self).is_in_database():
            db_operation = self.get(self.id)
            return db_operation.containing_blocks == self.containing_blocks
        else:
            return False

    def put(self, block_rev):
        """
        Put the operation as contained by a given block_rev.
        """
        print("Putting operation. cntblcks={}, block_rev.id={}".format(self.containing_blocks, block_rev.id))
        self.__add_containing_block(block_rev)
        print("... cntblk={}".format(self.containing_blocks))
        super(Operation, self).put()  # TODO what if it will throw an exception?

    def remove(self, block_rev):
        # When the containing_blocks tuple is cleared, we can remove operation. We don't need to check if there are any
        # operations with previous_operation set to the removing one, because no operations like this can exist. We're
        # removing op. only when we can remove block (the last one of containing_blocks), thus there is no other blocks
        # after that -- no other operations. If there was another operation after removing one in the same block -- we
        # will also remove it, because it's contained by only one -- being removed -- block.
        self.__remove_containing_block(block_rev)
        if len(self.containing_blocks) == 0:
            super(Operation, self).remove()

    # Exceptions

    class UUIDError(Exception):
        pass
