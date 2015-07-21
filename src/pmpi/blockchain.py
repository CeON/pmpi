from collections import deque

from pmpi.block import Block, BlockRev
from pmpi.exceptions import ObjectDoesNotExist


class BlockChain:
    class Record:
        FIELD_NAMES = ('depth', 'previous_id', 'next_ids')

        def __init__(self, depth, previous_id, next_ids):
            self.__depth = depth
            self.__previous_id = previous_id
            self.__next_ids = next_ids

        @property
        def depth(self):
            return self.__depth

        @property
        def previous_id(self):
            return self.__previous_id

        @property
        def next_ids(self):
            return self.__next_ids

        def __eq__(self, other):
            return self.depth == other.depth and self.previous_id == other.previous_id \
                and self.next_ids == other.next_ids

        class DoesNotExist(ObjectDoesNotExist):
            pass

    def __init__(self):
        self.__map = {}
        queue = deque()

        for revision_id in Block.get_revision_id_list():
            block = Block.get(revision_id)

            if bytes(block.previous_block) in self.__map:
                self.__modify_record(bytes(block.previous_block), next_ids=lambda x: x + (revision_id,))
            else:
                self.__map[bytes(block.previous_block)] = self.Record(None, None, (revision_id,))

            if revision_id in self.__map:
                self.__modify_record(revision_id, previous_id=lambda _: bytes(block.previous_block))
            else:
                self.__map[revision_id] = self.Record(None, bytes(block.previous_block), tuple())

        self.__modify_record(b'\x00' * 32, depth=lambda _: 0)
        queue.append(b'\x00' * 32)

        max_depth = -1
        self.__head = None

        while len(queue) > 0:
            rev = queue.popleft()
            depth = self.__map[rev].depth
            if depth > max_depth:
                max_depth = depth
                self.__head = rev
            self.__modify_record(rev, next_ids=lambda x: sorted(x))
            for next_rev in self.__map[rev].next_ids:
                self.__modify_record(next_rev, depth=lambda _: depth + 1)
                queue.append(next_rev)

    def __modify_record(self, revision_id, **kwargs):
        for field in kwargs:
            if field not in self.Record.FIELD_NAMES:
                raise KeyError("argument name out of the record fields")

        old_record = self.get_from_id(revision_id)
        new_kwargs = {
            field: kwargs[field](getattr(old_record, field)) if field in kwargs else getattr(old_record, field)
            for field in self.Record.FIELD_NAMES}
        self.__map[revision_id] = self.Record(**new_kwargs)

    def get_from_id(self, revision_id: bytes) -> Record:
        return self.__map[revision_id]

    def get_from_block_rev_id(self, block_rev_id: BlockRev):
        return self.get_from_id(bytes(block_rev_id))

    @property
    def head(self):
        return self.__head

    def __add_block(self, block_rev_id: BlockRev):
        if bytes(block_rev_id) in self.__map:
            raise self.BlockDuplication("block has already been added to the mapping")
        else:
            try:
                previous_id = bytes(block_rev_id.revision.previous_block)
                self.__modify_record(previous_id, next_ids=lambda x: sorted(x + (bytes(block_rev_id),)))
                self.__map[bytes(block_rev_id)] = self.Record(self.get_from_id(previous_id).depth + 1,
                                                              previous_id, tuple())
            except KeyError:
                raise self.Record.DoesNotExist("previous block id doesn't exist")

    class BlockDuplication(Exception):
        pass
