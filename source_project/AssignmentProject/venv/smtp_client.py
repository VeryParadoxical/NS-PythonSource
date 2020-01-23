__author__ = "Christopher Windmill, Brad Solomon"

__version__ = "1.0.1"
__status__ = "Development"

import socket
import selectors
import smtp_client_lib
# import traceback          PyCharm notes this is unused, I am unsure as it was present at base.


class NWSThreadedClient:
    # noinspection PyUnreachableCode
    def __init__(self, host="127.0.0.1", port=12345):
        if __debug__:
            print("NWSThreadedClient.__init__", host, port)

        # Network components
        self._host = host
        self._port = port
        self._listening_socket = None
        self._selector = selectors.DefaultSelector()

        self._module = None

    def start_connection(self, host, port):
        addr = (host, port)
        print("starting connection to", addr)

        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.setblocking(False)
        sock.connect_ex(addr)

        self._module = smtp_client_lib.Module(sock, addr)
        self._module.start()

    def run(self):
        self.start_connection(self._host, self._port)

        while True:
            user_action = input("MESSAGE: ")
            self._module.create_message(user_action)


if __name__ == "__main__":
    client = NWSThreadedClient()
    client.run()
