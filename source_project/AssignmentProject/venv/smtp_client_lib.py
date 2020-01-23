# import sys
# import json
# import io
# import struct
# PyCharm recognises the above as unused. Not sure if they are required as they were there at base.
import selectors
import queue
import traceback
import smtp_client_encryption
from threading import Thread


class Module(Thread):
    def __init__(self, sock, addr):
        Thread.__init__(self)

        self._selector = selectors.DefaultSelector()
        self._sock = sock
        self._addr = addr
        self._incoming_buffer = queue.Queue()
        self._outgoing_buffer = queue.Queue()
        self._state = "normal"
        self._sub_state = ""

        self.encryption = smtp_client_encryption.NWSEncryption()
        events = selectors.EVENT_READ | selectors.EVENT_WRITE
        self._selector.register(self._sock, events, data=None)

    # noinspection PyUnusedLocal,PyBroadException
    def run(self):
        try:
            while True:
                events = self._selector.select(timeout=1)
                for key, mask in events:
                    message = key.data
                    try:
                        if mask & selectors.EVENT_READ:
                            self._read()
                        if mask & selectors.EVENT_WRITE and not self._outgoing_buffer.empty():
                            self._write()
                    except Exception:
                        print(
                            "main: error: exception for",
                            f"{self._addr}:\n{traceback.format_exc()}",
                        )
                        self._sock.close()
                # Check for a socket being monitored to continue.
                if not self._selector.get_map():
                    break
        finally:
            self._selector.close()

    def _read(self):
        try:
            data = self._sock.recv(4096)
        except BlockingIOError:
            # Resource temporarily unavailable (errno EWOULDBLOCK)
            pass
        else:
            if data:
                self._incoming_buffer.put(self.encryption.decrypt(data.decode()))
            else:
                raise RuntimeError("Peer closed.")

        self._process_response()

    # noinspection PyUnusedLocal,PyPep8,PyBroadException
    def _write(self):
        try:
            message = self._outgoing_buffer.get_nowait()
        except:
            message = None

        if message:
            print("sending", repr(message), "to", self._addr)
            try:
                sent = self._sock.send(message)
            except BlockingIOError:
                # Resource temporarily unavailable (errno EWOULDBLOCK)
                pass

    def create_message(self, content):
        """
        This method will manage states during negotiation of both the encryption method and key via a
        diffie-helman key exchange. As messages are exchanged between the server and the client the sub state
        is incremented. This method functions in tandem with create message as user input is required.
        :param content:
        """
        if "ngtn" in content.lower() or " ngtn" in content.lower() and self._state != "data":
            self._state = "ngtn"
            if self._sub_state == "":
                __methods = self.encryption.generate_available_methods()
                if -1 in __methods:
                    content = "554 Transaction failed. No encryption available, killing connection, sorry."
                    self._state = "quit"
                    self.close()
                else:
                    self._sub_state = "1"  # 'choosing' avoids ambiguity with other sub state
                self._output(content)
                self.encryption.disable()

            elif self._sub_state == "2":
                _content = content.lower()
                if len(_content) > 5:
                    _choice = _content.split(' ')
                    success = self.encryption.validate_choice(_choice[1])
                    if success:
                        self.encryption.set_method(_choice[1])
                        self._output(_content)
                        self._sub_state = "3"
                    else:
                        print("Invalid choice detected, message not sent to server.")
                else:
                    print("Invalid choice detected, message not sent to server.")
        else:
            _value = content[0:3]
            if _value == "quit" and self._state != "data":
                self._state = "quit"
            self._output(content)

    def _output(self, content):
        __encoded = self.encryption.encrypt(content)
        __nwencoded = __encoded.encode()
        self._outgoing_buffer.put(__nwencoded)

    def _process_response(self):
        """
        This method will manage states during negotiation of both the encryption method and key via a
        diffie-helman key exchange. As messages are exchanged between the server and the client the substate
        is incremented. This method functions in tandem with create message as user input is required.
        This method handles generation and sending of an initial mixed key and the receiving of the servers
        mixed key producing a shared secret. Further this method handles the receiving and interpretation of
        the servers available encryption methods and compares it to the local list.
        """
        message = self._incoming_buffer.get()
        header_length = 3
        if self._state == "quit":
            self.close()
        elif len(message) >= header_length:
            print("Received:", message[0:header_length], message[header_length:])
        if self._state == "ngtn":
            if self._sub_state == "1" and "500" not in message and ":" in message:
                __incoming_list = []
                colon_split = message.split(":")
                values = colon_split[1]
                space_split = values.split(' ')
                # generate a list out of incoming message
                for value in space_split:
                    no_space_value = value.translate((None, ' '))
                    length = len(no_space_value)
                    if length > 0:
                        __incoming_list.append(value)
                __methods_list = self.encryption.get_methods()
                values = [value for value in __incoming_list if value in __methods_list]

                print("The following methods are shared between the client and server:")
                print("Shared methods are: ", values)
                print("Please enter your method choice as: NGTN <method>")
                self._sub_state = "2"

            elif self._sub_state == "3":
                self._sub_state = "4"
                self.encryption.generate_common_mix()
                values = ["NGTN", " COMMON MIX:", str(self.encryption.get_common_mix())]
                content = ''.join(values)
                encoded = self.encryption.encrypt(content)
                nwencoded = encoded.encode()
                self._outgoing_buffer.put(nwencoded)

            elif self._sub_state == "4":
                if " COMMON MIX:" in message:
                    values = message.split(" COMMON MIX:")
                    self.encryption.generate_shared_secret(values[1])
                    self.encryption.enable()
                    self._state = "normal"
                    self._sub_state = ""

            elif "Syntax error, command unrecognised" in message:
                print(message)

            else:
                print("There has been a communication error. Closing.")
                self._state = "quit"
                self.close()

    def close(self):
        print("closing connection to", self._addr)
        try:
            self._selector.unregister(self._sock)
        except Exception as e:
            print(
                f"error: selector.unregister() exception for",
                f"{self._addr}: {repr(e)}",
            )
        try:
            self._sock.close()
        except OSError as e:
            print(
                f"error: socket.close() exception for",
                f"{self._addr}: {repr(e)}",
            )
        finally:
            # Delete reference to socket object for garbage collection
            self._sock = None
