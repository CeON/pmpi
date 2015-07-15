from io import BytesIO
from ecdsa.keys import VerifyingKey, BadSignatureError
from src.pmpi.core import database_required, Database
from src.pmpi.exceptions import ObjectDoesNotExist, RawFormatError
from src.pmpi.operation import Operation
from src.pmpi.revision import AbstractRevision
from src.pmpi.utils import double_sha, read_bytes, read_uint32, read_sized_bytes


class BlockRev(AbstractRevision):
    def _get_revision_from_database(self):
        return Block.get(self._id)


class Block:
    """

    :type previous_block: BlockRev
    :type timestamp: int
    :type operations_hashes: list[bytes]
    :type operations: list[Operation]
    :type public_key: VerifyingKey
    :type signature: NoneType | bytes
    :type difficulty: int
    :type padding: int
    :type checksum: NoneType | bytes
    :type operations_limit: int
    """

    VERSION = 1

    def __init__(self, previous_block, timestamp, operations_hashes):
        """

        :type previous_block: BlockRev
        :type timestamp: int
        :type operations_hashes: list[bytes]
        :param previous_block: BlockRevID of the previous block
        :param timestamp: time of block creation
        :param operations_hashes: the list of operations' hashes that the new block will contain
        """
        self.previous_block = previous_block
        self.timestamp = timestamp
        self.operations_hashes = operations_hashes
        self.operations = []
        self.public_key = None
        self.signature = None

        self.difficulty = 1  # TODO what value should be the default, and what does the difficulty mean in particular?
        self.padding = 0
        self.checksum = None

        self.operations_limit = 5  # TODO what value should be the default?

    @classmethod
    def from_operations_list(cls, previous_block, timestamp, operations):
        block = cls(previous_block, timestamp, [op.hash() for op in operations])
        block.operations = operations
        return block

    def checksum_correct(self):
        """
        Check if checksum is correct.
        :return: True or raise exception
        :raise self.VerifyError: on the checksum mismatch
        """
        if self.checksum == double_sha(self.unmined_raw()):
            return True
        else:
            raise self.VerifyError("wrong checksum")

    def verify_signature(self):
        """
        Check if block is signed correctly.
        :return: True or raise exception
        :raise self.VerifyError: when the block isn't signed or self.unsigned_raw doesn't match the signature
        """
        if self.signature is not None:
            try:
                self.public_key.verify(self.signature, self.unsigned_raw())
            except BadSignatureError:
                raise self.VerifyError("wrong signature")

            return True
        else:
            raise self.VerifyError("block is not signed")

    def verify_revision_id(self, revision_id):
        if revision_id != self.hash():
            raise self.VerifyError("wrong revision_id")

    def refresh_operations(self):
        try:
            if self.operations_hashes != [op.hash() for op in self.operations]:
                self.operations = [Operation.get(h) for h in self.operations_hashes]
        except Operation.VerifyError:
            raise self.VerifyError("at least one of the operations is not properly signed")

    def verify(self):  # FIXME
        self.verify_signature()
        self.refresh_operations()

        for op in self.operations:
            op.verify()
        # TODO verify, if operations don't make trees instead of chains

        try:
            prev_block = self.previous_block.get_revision()
            if prev_block is not None:
                pass  # TODO check integrity of operation chains
        except self.DoesNotExist:
            raise self.ChainError("previous_revision_id does not exist")

        # TODO check: len(self.operations) <= self.operations_limit <= CALC_OP_LIMIT_FOR_MINTER(self.public_key)
        # TODO check: difficulty is correctly set -- check block depth and self.difficulty <= DIFF_AT_DEPTH(depth)

        return True

    def mine(self):  # FIXME method currently for testing purposes
        unmined_raw = self.unmined_raw()
        assert 0 < self.difficulty < 256  # TODO ...
        target = ((1 << 256 - self.difficulty) - 1).to_bytes(32, 'big')

        self.padding = 0

        while double_sha(unmined_raw) > target:
            self.padding += 1
            unmined_raw = unmined_raw[:-4] + self.padding.to_bytes(4, 'big')

        self.checksum = double_sha(self.unmined_raw())

    def hash(self):
        return double_sha(self.raw())

    # Serialization and deserialization

    def operations_hashes_raw(self):
        self.refresh_operations()
        return len(self.operations_hashes).to_bytes(4, 'big') + b''.join(self.operations_hashes)
        # TODO should we check the correctness of operations??
        # try:
        #     return len(self.operations).to_bytes(4, 'big') + b''.join([op.hash() for op in self.operations])
        # except Operation.VerifyError:
        #     raise self.VerifyError("at least one of the operations is not properly signed")

    def operations_full_raw(self):
        self.refresh_operations()
        # try:
        return len(self.operations).to_bytes(4, 'big') + b''.join(
            [len(op_raw).to_bytes(4, 'big') + op_raw for op_raw in [op.raw() for op in self.operations]])
        # except Operation.VerifyError:
        #     raise self.VerifyError("at least one of the operations is not properly signed")

    def unmined_raw(self):
        ret = self.VERSION.to_bytes(4, 'big')
        ret += bytes(self.previous_block)
        ret += self.timestamp.to_bytes(4, 'big')
        ret += self.operations_limit.to_bytes(4, 'big')
        ret += self.operations_hashes_raw()
        ret += self.difficulty.to_bytes(4, 'big')
        ret += self.padding.to_bytes(4, 'big')
        return ret

    def unsigned_raw(self):
        if self.checksum_correct():
            return self.unmined_raw() + self.checksum

    def raw(self):
        self.verify_signature()

        ret = self.unsigned_raw()
        ret += len(self.public_key.to_der()).to_bytes(4, 'big') + self.public_key.to_der()
        ret += len(self.signature).to_bytes(4, 'big') + self.signature
        return ret

    def raw_with_operations(self):
        ret = self.operations_full_raw()
        ret += self.raw()
        return ret

    @classmethod
    def __from_raw_without_verifying(cls, raw):
        buffer = BytesIO(raw)

        if read_uint32(buffer) != cls.VERSION:
            raise RawFormatError("version number mismatch")

        previous_block = BlockRev.from_id(read_bytes(buffer, 32))
        timestamp = read_uint32(buffer)
        operations_limit = read_uint32(buffer)

        operations_hashes = [read_bytes(buffer, 32) for _ in range(read_uint32(buffer))]

        # if operations is None:
        #     operations = timer(lambda:[Operation.get(h) for h in operations_hashes])()
        # else:
        #     for (h, op) in zip(operations_hashes, operations):
        #         if h != op.hash():
        #             raise cls.VerifyError("wrong given operations list")

        difficulty = read_uint32(buffer)
        padding = read_uint32(buffer)
        checksum = read_bytes(buffer, 32)
        public_key = VerifyingKey.from_der(read_sized_bytes(buffer))
        signature = read_sized_bytes(buffer)

        if len(buffer.read()) > 0:
            raise RawFormatError("raw input too long")

        if int.from_bytes(previous_block.get_id(), 'big') == 0:
            previous_block = BlockRev()

        block = cls(previous_block, timestamp, operations_hashes)
        block.operations_limit = operations_limit
        block.difficulty = difficulty
        block.padding = padding
        block.checksum = checksum
        block.public_key = public_key
        block.signature = signature

        return block

    @classmethod
    def __from_raw_and_operations(cls, raw, operations):
        block = cls.__from_raw_without_verifying(raw)
        if operations is not None:
            for (h, op) in zip(block.operations_hashes, operations):
                if h != op.hash():
                    raise cls.VerifyError("wrong given operations list")
            block.operations = operations
        block.verify()
        return block

    @classmethod
    def from_raw(cls, raw):
        return cls.__from_raw_and_operations(raw, None)

    @classmethod
    def from_raw_with_operations(cls, raw):
        buffer = BytesIO(raw)
        operations = [Operation.from_raw(read_sized_bytes(buffer)) for _ in range(read_uint32(buffer))]

        return cls.__from_raw_and_operations(buffer.read(), operations)

    # Database operations

    @classmethod
    @database_required
    def get_revision_id_list(cls, database):
        return database.keys(Database.BLOCKS)

    @classmethod
    @database_required
    def get(cls, database, revision_id):
        try:
            block = Block.__from_raw_without_verifying(database.get(Database.BLOCKS, revision_id))
            # TODO without verifying??
            # block.verify_revision_id(revision_id)
            # TODO .put() DO verify block... Without this line, getting blocks is much faster
            # TODO (there is no need to get block's operations from the database).
            return block
        except KeyError:
            raise cls.DoesNotExist

    @database_required
    def get_blockchain(self, database):
        raise NotImplementedError  # TODO

    @database_required
    def put(self, database):
        self.verify()
        revision_id = self.hash()

        try:
            self.get(revision_id)
            raise self.ChainError("revision_id already in database")
        except self.DoesNotExist:
            database.put(Database.BLOCKS, self.hash(), self.raw())

            # TODO is it right place for doing this (putting operations, as below) ??
            # TODO (and, shouldn't we catch any exceptions, e.g. Operation.ChainError, should we?)

            for op in self.operations:
                op.put()

    @database_required
    def remove(self, database):
        revision_id = self.hash()

        # FIXME naive algorithm !!!
        for rev in Block.get_revision_id_list():
            block = Block.get(rev)
            if block.previous_block.get_id() == revision_id:
                raise self.ChainError("can't remove: blocked by another block")

        try:
            database.delete(Database.BLOCKS, revision_id)

            # TODO when putting block, we are (currently) putting also operations. Should we remove them here?
            self.refresh_operations()
            for op in self.operations:
                op.remove()

        except ObjectDoesNotExist:
            raise self.DoesNotExist

    # Exceptions

    class ChainError(Exception):
        pass

    class DoesNotExist(ObjectDoesNotExist):
        pass

    class VerifyError(Exception):
        pass

