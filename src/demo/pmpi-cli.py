import sys
import time

sys.path.append('..')

import asyncio
import getopt
import binascii
from unittest.mock import patch
from ecdsa import SigningKey
from pmpi.block import Block, BlockRev
from pmpi.operation import Operation, OperationRev
from pmpi.blockchain import BlockChain
from pmpi.user import User
from pmpi.identifier import Identifier
import pmpi.core

patch.object = patch.object

is_miner = False
io_queue = asyncio.Queue()
block_queue = asyncio.Queue()
operation_queue = asyncio.Queue()

MIN_OPS_IN_BLOCK = 2


class ClientProtocol(asyncio.Protocol):
    def __init__(self, user, loop):
        self.user = user
        self.loop = loop
        self.transport = None

        pmpi.core.initialise_database('database_pmpi_' + binascii.hexlify(user._public_key.der).decode()[-6:])

    def connection_made(self, transport):
        self.transport = transport
        self.transport.write(self.user._public_key.der)
        print("\nPMPI User/Miner Console\n(type 'help' for help, 'exit' for exit)")
        self._add_input_callback()

    def data_received(self, data):
        if data[:2] == b'OP':
            print("Operation received.")
            self.process_operation(data[2:])
        elif data[:2] == b'BL':
            print("Block received")
            self.process_block(data[2:])
        else:
            print("Data not recognized.")

    def connection_lost(self, exc):
        print('The server closed the connection')
        self.loop.stop()

    def input_callback(self, future):
        line = future.result().strip()

        if line == "exit":
            self.transport.close()
        elif line == "help":
            print(
                " HELP\n"
                "======\n"
                "Available commands:\n"
                "- exit   -- exit\n"
                "- help   -- show this message\n"
                "- uuids  -- list minted uuids\n"
                "- new op -- create operation\n"
            )
            self._add_input_callback()
        elif line == "uuids":
            print(" UUIDS\n=======")
            print("\nUUIDS minted: {}\n".format(self.show_uuids()))
            self._add_input_callback()
        elif line == "new op":
            self.new_operation()
            self._add_input_callback()
        else:
            print("Unknown command. Type 'help' for list of available commands.")
            self._add_input_callback()

    def _add_input_callback(self):
        future = asyncio.ensure_future(io_queue.get())
        future.add_done_callback(self.input_callback)

    @staticmethod
    def show_uuids():
        uuid_list = Identifier.get_uuid_list()
        digits = len(str(len(uuid_list)))
        for index, identifier in enumerate(Identifier.get_uuid_list()):
            print("{}) {} | {}".format(str(index).rjust(digits), identifier, Identifier.get(identifier).operation_rev.obj.address))
        return len(uuid_list)

    def new_operation(self):
        print("Choose UUID:")
        uuids_number = self.show_uuids()
        print('\n {}) mint new uuid'.format(uuids_number))

        def send_operation(operation):
            self.user.sign_object(operation)
            x = None
            while x not in ('y', 'n'):
                x = input("Send operation? (y/n) ")
            if x == 'y':
                self.transport.write(b'OP' + operation.raw())  # TODO also -- length of operation?

        try:
            x = int(input("index="))
            if x < uuids_number:
                uuid = Identifier.get_uuid_list()[x]
                operation = Identifier.get(uuid).operation_rev.obj

                if self.user._public_key.der not in operation.owners_der:
                    print("You do not own this identifier!")
                    return
                # TODO show sth

                address = input("address=")
                # TODO owners choose owners
                send_operation(Operation(operation.get_rev(), address, [self.user._public_key]))
            elif x == uuids_number:
                address = input("address=")
                # TODO owners choose owners
                send_operation(Operation(OperationRev(), address, [self.user._public_key]))
            else:
                print("Wrong number.")

        except ValueError:
            print("Value Error, aborting.")

    def process_operation(self, raw_operation):
        op = Operation.from_raw(raw_operation)
        future = asyncio.ensure_future(operation_queue.put(op))
        future.add_done_callback(self.new_block)

    def new_block(self, result):
        print("New block... Operations in queue: {}".format(operation_queue.qsize()))
        ops = []

        def clean_queue():
            if not operation_queue.empty():
                future = asyncio.ensure_future(operation_queue.get())
                future.add_done_callback(get_from_queue_cb)
            else:
                mint_block()

        def get_from_queue_cb(future):
            op = future.result()
            try:
                Operation.get(op.id)
            except Operation.DoesNotExist:
                ops.append(op)
                clean_queue()

        clean_queue()

        def mint_block():

            if len(ops) >= MIN_OPS_IN_BLOCK:
                print("Preparing block with {} operations.".format(len(ops)))

                blockchain = pmpi.core.get_blockchain()
                rev = BlockRev.from_id(blockchain.head) if blockchain.max_depth > 0 else BlockRev()
                block = Block.from_operations_list(rev, int(time.time()), ops)
                block.difficulty = 10  # TODO difficulty!
                block.mine()
                self.user.sign_object(block)
                block.verify()

                print("Block minted. Sending.")

                self.transport.write(b'BL' + block.raw_with_operations())
            else:
                print("There are not enough operations to mint a block")
                for op in ops:
                    asyncio.ensure_future(operation_queue.put(op))


    def process_block(self, raw_block):
        block = Block.from_raw_with_operations(raw_block)

        with patch.object(BlockChain, '_get_new_blocks', return_value=[block]):
            pmpi.core.get_blockchain().update_blocks()

# Miner initialisation

try:
    opts, args = getopt.getopt(sys.argv[1:], "hmk:")
except getopt.GetoptError:
    print(sys.argv[0], "[-m] [-k <private key>]")
    sys.exit(2)

private_key = None

for opt, arg in opts:
    if opt == '-h':
        print(sys.argv[0], "[-m] [-k <private key>]")
        sys.exit()
    elif opt == '-k':
        private_key = SigningKey.from_der(binascii.unhexlify(arg))
    elif opt == '-m':
        is_miner = True

if private_key is None:
    private_key = SigningKey.generate()
    print("Private key:")
    print(binascii.hexlify(private_key.to_der()).decode())

user = User(private_key)

print("Starting...")

# Asyncio

loop = asyncio.get_event_loop()
loop.add_reader(sys.stdin, lambda q: asyncio.ensure_future(q.put(sys.stdin.readline())), io_queue)

coroutine = loop.create_connection(lambda: ClientProtocol(user, loop), '127.0.0.1', 8888)
loop.run_until_complete(coroutine)
loop.run_forever()

# end = False
# while not end:
#     try:
#         loop.run_forever()
#         end = True
#     except KeyboardInterrupt:
#         print("\nTo exit, type 'exit'.")

loop.close()
