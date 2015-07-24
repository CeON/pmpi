from io import BytesIO
from pmpi.exceptions import RawFormatError
from pmpi.operation import Operation
from pmpi.utils import double_sha, read_bytes, read_uint32, read_sized_bytes
from pmpi.public_key import PublicKey

import pmpi.abstract
import pmpi.core


class BlockRev(pmpi.abstract.AbstractRevision):
    def _get_revision_from_database(self):
        return Block.get(self.id)


class Block(pmpi.abstract.AbstractSignedObject):
    """

    :type previous_block_rev: BlockRev
    :type timestamp: int
    :type __operations_ids: tuple[bytes]
    :type __operations: tuple[Operation]
    :type difficulty: int
    :type padding: int
    :type __checksum: NoneType | bytes
    :type operations_limit: int
    """

    VERSION = 1

    MIN_OPERATIONS = 2
    MAX_OPERATIONS = 10

    def __init__(self, previous_block_rev, timestamp, operations_ids):
        """

        :type previous_block_rev: BlockRev
        :type timestamp: int
        :type operations_ids: tuple[bytes]
        :param previous_block_rev: BlockRevID of the previous block
        :param timestamp: time of block creation
        :param operations_ids: the list of operations' hashes that the new block will contain
        """

        self.previous_block_rev = previous_block_rev
        self.timestamp = timestamp
        self.__operations_ids = tuple(operations_ids)
        self.__operations = tuple()

        self.difficulty = 1
        self.padding = 0
        self.__checksum = None

        self.operations_limit = self.MAX_OPERATIONS

    @classmethod
    def from_operations_list(cls, previous_block_rev, timestamp, operations):
        try:
            block = cls(previous_block_rev, timestamp, [op.id for op in operations])
            block.__operations = tuple(operations)
            return block
        except Operation.VerifyError:
            raise cls.VerifyError("at least one of the operations is not properly signed")

    # Getters and setters

    @property
    def operations_ids(self):
        return self.__operations_ids

    @property
    def operations(self):
        self._update_operations()
        return self.__operations

    def extend_operations(self, new_operations):
        self.__operations += tuple(new_operations)
        self.__operations_ids += tuple(op.id for op in new_operations)

    def is_checksum_correct(self):
        """
        Check if checksum is correct.
        """
        return self.__checksum == double_sha(self.unmined_raw())

    @property
    def requires_signature_verification(self):
        return (not self.is_checksum_correct()) or super(Block, self).requires_signature_verification

    # Serialization and deserialization

    def operations_ids_raw(self):
        self._update_operations()
        return len(self.operations_ids).to_bytes(4, 'big') + b''.join(self.operations_ids)

    def operations_full_raw(self):
        return len(self.operations).to_bytes(4, 'big') + b''.join(
            [len(op_raw).to_bytes(4, 'big') + op_raw for op_raw in [op.raw() for op in self.operations]])

    def unmined_raw(self):
        ret = self.VERSION.to_bytes(4, 'big')
        ret += self.previous_block_rev.id
        ret += self.timestamp.to_bytes(4, 'big')
        ret += self.operations_limit.to_bytes(4, 'big')
        ret += self.operations_ids_raw()
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

        previous_block_rev = BlockRev.from_id(read_bytes(buffer, 32))
        timestamp = read_uint32(buffer)
        operations_limit = read_uint32(buffer)

        operations_ids = [read_bytes(buffer, 32) for _ in range(read_uint32(buffer))]
        difficulty = read_uint32(buffer)
        padding = read_uint32(buffer)
        checksum = read_bytes(buffer, 32)
        public_key_der = read_sized_bytes(buffer)
        signature = read_sized_bytes(buffer)

        if len(buffer.read()) > 0:
            raise RawFormatError("raw input too long")

        if int.from_bytes(previous_block_rev.id, 'big') == 0:
            previous_block_rev = BlockRev()

        block = cls(previous_block_rev, timestamp, operations_ids)
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
            for (h, op) in zip(block.operations_ids, operations):
                if h != op.id:
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
        try:
            if self.operations_ids != tuple(op.id for op in self.__operations):
                self.__operations = tuple(Operation.get(h) for h in self.operations_ids)
        except Operation.VerifyError:
            raise self.VerifyError("at least one of the operations is not properly signed")

    def verify(self):
        self.verify_signature()

        operations_counter = {h: 0 for h in self.operations_ids}
        for op in self.operations:
            op.verify()
            if op.previous_operation_rev.id in operations_counter:
                operations_counter[op.previous_operation_rev.id] += 1

        if not all([count <= 1 for count in operations_counter.values()]):
            raise self.ChainError("operations are creating tree inside the block")

        try:
            prev_block = self.previous_block_rev.obj
            if prev_block is not None:
                pass  # TODO check integrity of operation chains.
                # TODO also: should it check if the previous block is in the database?
                # TODO [or should it be moved to put_verify?]
        except self.DoesNotExist:
            raise self.ChainError("previous_revision_id does not exist")

        if not self.MIN_OPERATIONS <= self.operations_limit <= self.MAX_OPERATIONS:
            raise self.VerifyError("operations_limit out of range")

        if not self.MIN_OPERATIONS <= len(self.operations) <= self.operations_limit:
            raise self.VerifyError("number of operations doesn't satisfy limitations")

        # TODO check: difficulty is correctly set -- check block depth and self.difficulty <= DIFF_AT_DEPTH(depth)

        return True

    @pmpi.core.database_required
    def put_verify(self, database):
        prev_block = self.previous_block_rev.obj
        if prev_block is None:
            if len(database.blockchain.get(BlockRev().id).next_ids) > 0:
                raise Block.GenesisBlockDuplication("trying to create multiple genesis blocks")

    @pmpi.core.database_required
    def remove_verify(self, database):
        if len(database.blockchain.get(self.id).next_ids) > 0:
            raise self.ChainOperationBlockedError("can't remove: blocked by another block")

    # Mine

    def mine(self):
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
        return pmpi.core.Database.BLOCKS

    @pmpi.core.database_required
    def put(self, database):
        print(''.join(["{:02x}".format(x) for x in self.id]), "-- PUT --")
        super(Block, self).put()
        database.blockchain.add_block(self)

        for op in self.operations:
            op.put(BlockRev.from_revision(self))

    @pmpi.core.database_required
    def remove(self, database):
        super(Block, self).remove()
        database.blockchain.remove_block(self)

        # op.remove is actually smart -- removes operation only if it isn't needed any more.
        for op in self.operations:
            op.remove(BlockRev.from_revision(self))

    # Exceptions

    class GenesisBlockDuplication(pmpi.abstract.AbstractSignedObject.DuplicationError):
        pass
