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

        old_record = self.get(revision_id)
        new_kwargs = {
            field: kwargs[field](getattr(old_record, field)) if field in kwargs else getattr(old_record, field)
            for field in self.Record.FIELD_NAMES}
        self.__map[revision_id] = self.Record(**new_kwargs)

    def __add_block(self, block_rev_id: BlockRev):
        if bytes(block_rev_id) in self.__map:
            raise self.BlockDuplication("block has already been added to the mapping")
        else:
            try:
                previous_id = bytes(block_rev_id.revision.previous_block)
                self.__modify_record(previous_id, next_ids=lambda x: sorted(x + (bytes(block_rev_id),)))
                self.__map[bytes(block_rev_id)] = self.Record(self.get(previous_id).depth + 1,
                                                              previous_id, tuple())
            except KeyError:
                raise self.Record.DoesNotExist("previous block id doesn't exist")

    def get(self, revision_id: bytes) -> Record:
        return self.__map[revision_id]

    # def get_from_block_rev_id(self, block_rev_id: BlockRev):
    #     return self.get_from_id(bytes(block_rev_id))

    @property
    def head(self):
        return self.__head

    @property
    def max_depth(self):
        return self.get(self.head).depth

    def update_blocks(self):
        new_max_depth = self.max_depth
        new_head = self.head

        for block in self.__get_new_blocks():
            # TODO some additional criteria for accepting block
            block.put()  # put() is making all needed validations before actually putting the block into the database
            block_rev = BlockRev.from_revision(block)
            self.__add_block(block_rev)
            record = self.get(bytes(block_rev))

            if record.depth > new_max_depth:
                new_max_depth = record.depth
                new_head = bytes(block_rev)

        if new_max_depth > self.max_depth:
            self.__set_head(new_head)

    def __get_new_blocks(self):
        raise NotImplementedError

    def __set_head(self, new_head_id):
        raise NotImplementedError

    def __lowest_common_ancestor(self, block_rev1, block_rev2):
        records = [(bytes(rev), self.get(bytes(rev))) for rev in (block_rev1, block_rev2)]
        if records[0][1].depth < records[1][1].depth:
            records.reverse()
        while records[0][1].depth > records[1][1].depth:
            records[0] = (records[0][1].previous_id, self.get(records[0][1].previous_id))
        while records[0][0] != records[1][0]:
            records = [(rev_id, self.get(rev_id)) for rev_id in (record[1].previous_id for record in records)]
        return records[0][0]

    class BlockDuplication(Exception):
        pass
