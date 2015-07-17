from io import BytesIO
from pmpi.abstract_revision import AbstractRevision

from pmpi.core import database_required, Database
from pmpi.exceptions import RawFormatError
from pmpi.operation import Operation
from pmpi.utils import double_sha, read_bytes, read_uint32, read_sized_bytes
from pmpi.public_key import PublicKey
from pmpi.abstract_signed_object import AbstractSignedObject


class BlockRev(AbstractRevision):
    def _get_revision_from_database(self):
        return Block.get(self._id)


class Block(AbstractSignedObject):
    """

    :type previous_block: BlockRev
    :type timestamp: int
    :type __operations_hashes: tuple[bytes]
    :type __operations: tuple[Operation]
    :type difficulty: int
    :type padding: int
    :type __checksum: NoneType | bytes
    :type operations_limit: int
    """

    VERSION = 1

    MIN_OPERATIONS = 2
    MAX_OPERATIONS = 10

    def __init__(self, previous_block, timestamp, operations_hashes):
        """

        :type previous_block: BlockRev
        :type timestamp: int
        :type operations_hashes: tuple[bytes]
        :param previous_block: BlockRevID of the previous block
        :param timestamp: time of block creation
        :param operations_hashes: the list of operations' hashes that the new block will contain
        """

        self.previous_block = previous_block
        self.timestamp = timestamp
        self.__operations_hashes = tuple(operations_hashes)
        self.__operations = tuple()

        self.difficulty = 1  # TODO what value should be the default, and what does the difficulty mean in particular?
        self.padding = 0
        self.__checksum = None

        self.operations_limit = self.MAX_OPERATIONS

    @classmethod
    def from_operations_list(cls, previous_block, timestamp, operations):
        try:
            block = cls(previous_block, timestamp, [op.hash() for op in operations])
            block.__operations = tuple(operations)
            return block
        except Operation.VerifyError:
            raise cls.VerifyError("at least one of the operations is not properly signed")

    # Getters and setters

    @property
    def operations_hashes(self):
        return self.__operations_hashes

    @property
    def operations(self):
        self._update_operations()
        return self.__operations

    def extend_operations(self, new_operations):
        self.__operations += tuple(new_operations)
        self.__operations_hashes += tuple(op.hash() for op in new_operations)

    def is_checksum_correct(self):
        """
        Check if checksum is correct.
        """
        return self.__checksum == double_sha(self.unmined_raw())

    @property
    def requires_signature_verification(self):
        return (not self.is_checksum_correct()) or super(Block, self).requires_signature_verification

    # Serialization and deserialization

    def operations_hashes_raw(self):
        self._update_operations()
        return len(self.operations_hashes).to_bytes(4, 'big') + b''.join(self.operations_hashes)

    def operations_full_raw(self):
        return len(self.operations).to_bytes(4, 'big') + b''.join(
            [len(op_raw).to_bytes(4, 'big') + op_raw for op_raw in [op.raw() for op in self.operations]])

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
        if self.is_checksum_correct():
            return self.unmined_raw() + self.__checksum
        else:
            raise self.VerifyError("wrong checksum")

    def raw_with_operations(self):
        ret = self.operations_full_raw()
        ret += self.raw()
        return ret

    @classmethod
    def _from_raw_without_verifying(cls, raw):
        buffer = BytesIO(raw)

        if read_uint32(buffer) != cls.VERSION:
            raise RawFormatError("version number mismatch")

        previous_block = BlockRev.from_id(read_bytes(buffer, 32))
        timestamp = read_uint32(buffer)
        operations_limit = read_uint32(buffer)

        operations_hashes = [read_bytes(buffer, 32) for _ in range(read_uint32(buffer))]
        difficulty = read_uint32(buffer)
        padding = read_uint32(buffer)
        checksum = read_bytes(buffer, 32)
        public_key_der = read_sized_bytes(buffer)  # VerifyingKey.from_der(read_sized_bytes(buffer))
        signature = read_sized_bytes(buffer)

        if len(buffer.read()) > 0:
            raise RawFormatError("raw input too long")

        if int.from_bytes(previous_block.id, 'big') == 0:
            previous_block = BlockRev()

        block = cls(previous_block, timestamp, operations_hashes)
        block.operations_limit = operations_limit
        block.difficulty = difficulty
        block.padding = padding
        block.__checksum = checksum
        block.sign(PublicKey(public_key_der), signature)

        return block

    @classmethod
    def __from_raw_and_operations(cls, raw, operations):
        block = cls._from_raw_without_verifying(raw)
        if operations is not None:
            for (h, op) in zip(block.operations_hashes, operations):
                if h != op.hash():
                    raise cls.VerifyError("wrong given operations list")
            block.__operations = operations
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

    # Verification

    def _update_operations(self):
        # TODO when some of operations (objects) changes, it probably gets the old values from the database
        # TODO   or raise Operation.DoesNotExist (is it correct?)
        try:
            if self.operations_hashes != tuple(op.hash() for op in self.__operations):
                self.__operations = tuple(Operation.get(h) for h in self.operations_hashes)
        except Operation.VerifyError:
            raise self.VerifyError("at least one of the operations is not properly signed")

    def verify(self):  # FIXME
        self.verify_signature()

        for op in self.operations:
            op.verify()
        # TODO verify, if operations don't make trees instead of chains

        try:
            prev_block = self.previous_block.revision
            if prev_block is not None:
                pass  # TODO check integrity of operation chains
        except self.DoesNotExist:
            raise self.ChainError("previous_revision_id does not exist")

        if not self.MIN_OPERATIONS <= self.operations_limit <= self.MAX_OPERATIONS:
            raise self.VerifyError("operations_limit out of range")

        if not self.MIN_OPERATIONS <= len(self.operations) <= self.operations_limit:
            raise self.VerifyError("number of operations doesn't satisfy limitations")

        # TODO check: difficulty is correctly set -- check block depth and self.difficulty <= DIFF_AT_DEPTH(depth)

        return True

    def put_verify(self):
        pass  # TODO?

    def remove_verify(self):
        revision_id = self.hash()

        # FIXME naive algorithm !!!
        for rev in Block.get_revision_id_list():
            block = Block.get(rev)
            if block.previous_block.id == revision_id:
                raise self.ChainError("can't remove: blocked by another block")

    # Mine

    def mine(self):  # FIXME method currently for testing purposes
        unmined_raw = self.unmined_raw()
        assert 0 < self.difficulty < 256  # TODO ...
        target = ((1 << 256 - self.difficulty) - 1).to_bytes(32, 'big')

        self.padding = 0

        while double_sha(unmined_raw) > target:
            self.padding += 1
            unmined_raw = unmined_raw[:-4] + self.padding.to_bytes(4, 'big')

        self.__checksum = double_sha(self.unmined_raw())

    # Database operations

    @classmethod
    def _get_dbname(cls):
        return Database.BLOCKS

    @database_required
    def get_blockchain(self, database):
        raise NotImplementedError  # TODO

    @database_required
    def put(self, database):
        super(Block, self).put()

        # TODO is it right place for doing this (putting operations, as below) ??
        # TODO (and, shouldn't we catch any exceptions, e.g. Operation.ChainError, should we?)

        for op in self.operations:
            try:
                op.put()
            except Operation.ChainError as e:
                print(e, str(e))  # TODO

    @database_required
    def remove(self, database):
        super(Block, self).remove()
        # TODO when putting block, we are (currently) putting also operations. Should we remove them here?
        # self.refresh_operations()
        for op in self.operations:
            op.remove()
