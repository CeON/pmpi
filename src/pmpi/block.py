from io import BytesIO
from ecdsa.keys import VerifyingKey, BadSignatureError
from src.pmpi.core import database_required
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
    :type operations: list[Operation]
    :type public_key: VerifyingKey
    :type signature: NoneType | bytes
    :type difficulty: int
    :type padding: int
    :type checksum: NoneType | bytes
    :type operations_limit: int
    """

    VERSION = 1

    def __init__(self, previous_block, timestamp, operations):
        """

        :type previous_block: BlockRev
        :type timestamp: int
        :type operations: list[Operation]
        :param previous_block: BlockRevID of the previous block
        :param timestamp: time of block creation
        :param operations: the list of operations that the new block will contain
        """
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
        """
        :rtype : bytes
        :return: calculated checksum used for fulfilling the proof-of-work
        """
        return double_sha(self.unmined_raw())

    def checksum_correct(self):
        """
        Check if checksum is correct.
        :return: True or raise exception
        :raise self.VerifyError: on the checksum mismatch
        """
        if self.checksum == self.counted_checksum():
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

    def mine(self):  # FIXME method currently for testing purposes
        unmined_raw = self.unmined_raw()
        assert 0 < self.difficulty < 256  # TODO ...
        target = ((1 << 256 - self.difficulty) - 1).to_bytes(32, 'big')

        self.padding = 0

        while double_sha(unmined_raw) > target:
            self.padding += 1
            unmined_raw = unmined_raw[:-4] + self.padding.to_bytes(4, 'big')

        self.checksum = self.counted_checksum()

    def verify(self):  # FIXME
        self.verify_signature()

        for op in self.operations:
            op.verify()
        # TODO verify, if operations don't make trees instead of chains

        try:
            prev_block = self.previous_block.get_revision()
            if prev_block is not None:
                pass  # TODO check itegrity of operation chains
        except self.DoesNotExist:
            raise self.ChainError("previous_revision_id does not exist")

        # TODO check: len(self.operations) <= self.operations_limit <= CALC_OP_LIMIT_FOR_MINTER(self.public_key)
        # TODO check: difficulty is correctly set -- check block depth and self.difficulty <= DIFF_AT_DEPTH(depth)

        return True

    def hash(self):
        return double_sha(self.raw())

    # Serialization and deserialization

    def operations_raw(self):
        try:
            return len(self.operations).to_bytes(4, 'big') + b''.join(
                [len(op).to_bytes(4, 'big') + op for op in [op.raw() for op in self.operations]])
        except Operation.VerifyError:
            raise self.VerifyError("at least one of the operations is not properly signed")

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
        self.verify_signature()

        ret = self.unsigned_raw()
        ret += len(self.public_key.to_der()).to_bytes(4, 'big') + self.public_key.to_der()
        ret += len(self.signature).to_bytes(4, 'big') + self.signature
        return ret

    @classmethod
    def from_raw(cls, revision_id, raw):  # FIXME
        if len(revision_id) != 32:
            raise cls.VerifyError("wrong revision_id")

        buffer = BytesIO(raw)

        if read_uint32(buffer) != cls.VERSION:
            raise RawFormatError("version number mismatch")

        previous_block = BlockRev.from_id(read_bytes(buffer, 32))
        timestamp = read_uint32(buffer)
        operations_limit = read_uint32(buffer)
        operations = [Operation.from_raw(op) for op in
                      [read_sized_bytes(buffer) for _ in range(read_uint32(buffer))]]
        difficulty = read_uint32(buffer)
        padding = read_uint32(buffer)
        checksum = read_bytes(buffer, 32)
        public_key = VerifyingKey.from_der(read_sized_bytes(buffer))
        signature = read_sized_bytes(buffer)

        if len(buffer.read()) > 0:
            raise RawFormatError("raw input too long")

        if int.from_bytes(previous_block.get_id(), 'big') == 0:
            previous_block = BlockRev()

        block = cls(previous_block, timestamp, operations)
        block.operations_limit = operations_limit
        block.difficulty = difficulty
        block.padding = padding
        block.checksum = checksum
        block.public_key = public_key
        block.signature = signature

        block.verify()

        if revision_id != block.hash():
            raise cls.VerifyError("wrong revision_id")

        return block

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

    class ChainError(Exception):
        pass

    class DoesNotExist(ObjectDoesNotExist):
        pass

    class VerifyError(Exception):
        pass
