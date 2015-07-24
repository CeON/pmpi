from collections import deque

from pmpi.exceptions import ObjectDoesNotExist
import pmpi.block


class BlockChain:
    class Record:
        FIELD_NAMES = ('depth', 'previous_id', 'next_ids')

        def __init__(self, depth, previous_id, next_ids):
            self.__depth = depth
            self.__previous_id = previous_id
            self.__next_ids = tuple(next_ids)

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
            for attr in self.FIELD_NAMES:
                if getattr(self, attr) != getattr(other, attr):
                    return False
            return True

        class DoesNotExist(ObjectDoesNotExist):
            pass

    def __init__(self):
        self.__map = {}
        queue = deque()

        for revision_id in pmpi.block.Block.get_revision_id_list():
            block = pmpi.block.Block.get(revision_id)

            if block.previous_block_rev.id in self.__map:
                self.__modify_record(block.previous_block_rev.id, next_ids=lambda x: x + (revision_id,))
            else:
                self.__map[block.previous_block_rev.id] = self.Record(None, None, (revision_id,))

            if revision_id in self.__map:
                self.__modify_record(revision_id, previous_id=lambda _: block.previous_block_rev.id)
            else:
                self.__map[revision_id] = self.Record(None, block.previous_block_rev.id, tuple())

        if len(self.__map) > 0:
            self.__modify_record(b'\x00' * 32, depth=lambda _: 0)
        else:
            self.__map[b'\x00' * 32] = self.Record(0, None, tuple())
        queue.append(b'\x00' * 32)

        self.__head = None

        while len(queue) > 0:
            rev = queue.popleft()
            depth = self.__map[rev].depth
            if depth > self.max_depth:
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

    def add_block(self, block):
        if block.id in self.__map:
            raise self.BlockDuplicationError("block has already been added to the mapping")
        else:
            try:
                previous_id = block.previous_block_rev.id
                self.__modify_record(previous_id, next_ids=lambda x: sorted(x + (block.id,)))
                self.__map[block.id] = self.Record(self.get(previous_id).depth + 1, previous_id, tuple())
            except KeyError:
                raise self.Record.DoesNotExist("previous block id doesn't exist")

    def remove_block(self, block):
        if block.id not in self.__map:
            raise pmpi.block.Block.DoesNotExist("block isn't in the blockchain")
        else:
            record = self.get(block.id)
            if len(record.next_ids) > 0:
                raise pmpi.block.Block.ChainOperationBlockedError("can't remove: block has following blocks")

            self.__modify_record(record.previous_id, next_ids=lambda x: tuple(ni for ni in x if ni != block.id))
            del self.__map[block.id]

            if self.head == block.id:
                # rebuild head and depth
                for key, record in self.__map.items():
                    if len(record.next_ids) == 0:
                        if record.depth > self.max_depth:
                            self.__head = key

                self.__set_head(self.__head)

    def get(self, revision_id: bytes) -> Record:
        try:
            return self.__map[revision_id]
        except KeyError:
            raise pmpi.block.Block.DoesNotExist("block isn't in the blockchain")

    def exist(self, revision_id: bytes):
        return revision_id in self.__map

    @property
    def head(self):
        return self.__head

    @property
    def max_depth(self):
        try:
            return self.get(self.head).depth
        except pmpi.block.Block.DoesNotExist:
            return -1

    def update_blocks(self):
        new_max_depth = self.max_depth
        new_head = self.head

        for block in self.__get_new_blocks():
            # TODO some additional criteria for accepting block

            block.put()  # put() is making all needed validations before actually putting the block into the database
            block_rev = pmpi.block.BlockRev.from_revision(block)
            record = self.get(block_rev.id)

            if record.depth > new_max_depth:
                new_max_depth = record.depth
                new_head = block_rev.id

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

    class BlockDuplicationError(Exception):
        pass

    # TODO delete this debug method:
    def show(self):
        print("SHOW BLOCKCHAIN")

        def s(b):
            return int(b[0])

        for k, record in self.__map.items():
            print("block:", s(k))
            print("previous:", s(record.previous_id) if record.previous_id is not None else "None")
            print("next:", [s(n) for n in record.next_ids])
            print("---")
