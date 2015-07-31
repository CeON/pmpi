import asyncio
import random
import sys
import binascii

clients = {}

# def got_stdin_data(q):
#     asyncio.ensure_future(q.put(sys.stdin.readline()))

class EchoServerClientProtocol(asyncio.Protocol):
    def __init__(self):
        self.transport = None
        self.key = None

    def connection_made(self, transport):
        peer_name = transport.get_extra_info('peername')
        print('Connection from {}'.format(peer_name))
        self.transport = transport

    def data_received(self, data):
        if self.key is None:
            self.key = data
            clients[self.key] = self
            print("Client added: {}".format(binascii.hexlify(self.key)[-6:].decode()))
        else:
            print("{} from {}".format(data[:2].decode(), binascii.hexlify(self.key)[-6:].decode()))
            for key, protocol in clients.items():
                    protocol.transport.write(data)
            print("Sent.")

    def connection_lost(self, exc):
        if self.key in clients:
            print("Goodbye, {}".format(binascii.hexlify(self.key)[-6:].decode()))
            del clients[self.key]


# q = asyncio.Queue()
loop = asyncio.get_event_loop()
# loop.add_reader(sys.stdin, got_stdin_data, q)
# Each client connection will create a new protocol instance
coroutine = loop.create_server(EchoServerClientProtocol, '127.0.0.1', 8888)
server = loop.run_until_complete(coroutine)

# Serve requests until CTRL+c is pressed
print('Serving on {}'.format(server.sockets[0].getsockname()))
try:
    loop.run_forever()
except KeyboardInterrupt:
    pass

# Close the server
server.close()
loop.run_until_complete(server.wait_closed())
loop.close()