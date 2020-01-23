import selectors
import queue
import traceback
import smtp_server_encryption
from threading import Thread
from os import path
import code_dictionary
import time
from datetime import datetime
import re
import json
import pathlib


def remove_space(message):
    """
    This function takes a string in and removes any spaces within and returning a string.
    :param message: string, some values you want spaces removing from.
    :return: string, with no spaces
    """
    _new_message = []
    for ch in message:
        if ch != ' ':
            _new_message.append(ch)
    _finished = ''.join(_new_message)
    return _finished


class Module(Thread):
    def __init__(self, sock, addr):
        Thread.__init__(self)
        self._selector = selectors.DefaultSelector()
        self._sock = sock
        self._addr = addr
        self._incoming_buffer = queue.Queue()
        self._outgoing_buffer = queue.Queue()
        self.encryption = smtp_server_encryption.NWSEncryption()
        self.return_codes = code_dictionary.ReturnCodeDictionary()

        self._last_time = time.time()
        self._timeout = 240  # Time before client gets timed out due to no response in seconds (s).
        self._my_initialise()  # Calls method to initialise. This is a method as it is required for the RSET command.

        success = self.encryption.create_log(self._sock, self._addr)
        if success:
            print("Log successfully created.")
        else:
            print("Log could not be created, closing.")
            self.close()
        self._reserved_domains = [".example", ".invalid", "example.com", "example.net", "example.org",
                                  ".test", ".invalid", ".localhost"]
        # Basic check for user-name & password file then generate all possible users into a list.
        if path.exists("Server\\UandP.txt") == 1:
            with open("Server\\UandP.txt", "r") as f:
                for line in f:
                    line_found = line.split(" ")
                    _file_username = line_found[0]
                    self._user_list.append(_file_username)
        else:
            self._create_message(self.return_codes.code_sort("471", self._state, "No users can be found."))
            self._state = "quit"
            self.close()

        if path.exists("Server\\Groups\\Groups.txt") == 1:
            with open("Server\\Groups\\Groups.txt", "r") as f:
                for line in f:
                    line_found = line.split(":")
                    _file_group = line_found[0]
                    self._group_list.append(_file_group)

        events = selectors.EVENT_READ | selectors.EVENT_WRITE
        self._selector.register(self._sock, events, data=None)

        self._create_message(self.return_codes.code_sort("220", self._state, self._my_domain))

    def _my_initialise(self):
        try:
            self._state = "start"
            self._sub_state = ""
            self._username = ""
            self._input_username = ""
            self._input_password = ""
            # Base key for all mail storage decryption and encryption.
            # Future implementations may wish to import a key from a file in the init and set it here.
            # Note: Message (communication) encryption keys are generated at runtime and negotiated via diffie-helman.
            # I recommend a range of -10 to +10. It's only caesar after all.
            self._base_key = 0
            self.encryption.set_base_key(self._base_key)
            self._login_attempts = 0
            self._logged_in = 0
            self._negotiated = 0
            self._user_list = []
            self._data_subject = ""
            self._data_body = ""
            self._mail_from_domain = ""
            self._receipt_list = []
            self._group_list = []
            self._file_flag = "False"
            self._my_domain = "mymaildomain.com"  #Change to alter the domain of this server.
            return True
        except (NameError, ValueError, TypeError):
            return False

    def refresh_timeout(self):
        """
        Simply refreshes the timeout. Called when the server receives something from the client.
        """
        self._last_time = time.time()

    # noinspection PyBroadException
    def run(self):
        try:
            while True:
                # Timeout check for client.
                current_time = time.time()
                if current_time - self._last_time > self._timeout:
                    self._create_message(self.return_codes.code_sort("420", self._state, ""))
                    self.close()
                events = self._selector.select(timeout=None)
                for key, mask in events:
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
                        self.encryption.log(
                            f"EXCEPTION: main: error: exception for {self._addr}:\n{traceback.format_exc()}",
                        )
                        self._sock.close()
                if not self._selector.get_map():
                    break
        except KeyboardInterrupt:
            print("caught keyboard interrupt, exiting")
            self.encryption.log("EXCEPTION: KeyboardInterrupt")
        finally:
            self._selector.close()

    def _read(self):
        try:
            data = self._sock.recv(4096)
        except BlockingIOError:
            print("blocked")
            self.encryption.log("EXCEPTION: BlockingIOError")
            # Resource temporarily unavailable (errno EWOULDBLOCK)
            pass
        else:
            if data:
                self._incoming_buffer.put(self.encryption.decrypt(data.decode()))
            else:
                raise RuntimeError("Peer closed.")

        self._process_response()

    # noinspection PyBroadException
    def _write(self):
        """
        Writes outgoing message
        """
        try:
            message = self._outgoing_buffer.get_nowait()
        except Exception:
            message = None

        if message:
            print("sending", repr(message), "to", self._addr)
            try:
                sent = self._sock.send(message)
            except BlockingIOError:
                # Resource temporarily unavailable (errno EWOULDBLOCK)
                pass

    def _create_message(self, content):
        """
        Creates an outgoing message to the client via encoding and encryption.
        :param content:
        """
        encoded = self.encryption.encrypt(content)
        nwencoded = encoded.encode()
        self._outgoing_buffer.put(nwencoded)

    def close(self):
        print("closing connection to", self._addr)
        self.encryption.log(f"closing connection to {self._addr}")
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
            self.encryption.log(f"error: socket.close() exception for {self._addr}: {repr(e)}")
            print(
                f"error: socket.close() exception for",
                f"{self._addr}: {repr(e)}",
            )
        finally:
            # Delete reference to socket object for garbage collection
            self._sock = None

    def _process_response(self):
        """
        Handles sub-states for multiline reponses during the data stage. Otherwise handles incoming messages and formats
        them as desired for input to module processor.
        """
        if self._state == "quit":
            self._create_message(self.return_codes.code_sort("421", self._state, self._my_domain))
            self.close()
        else:
            message = self._incoming_buffer.get()
            self.refresh_timeout()
            header_length = 4
            if self._state == "data":
                if self._state == "rcpt" and "data" in message.lower()[0:header_length]:
                    self.encryption.log("Received DATA.")
                    self._module_processor(message[0:header_length], message[header_length:])
                # This allows for further recipients to be adding during the data phase if desired.
                elif "rcpt" in message.lower()[0:header_length]:
                    if len(message) >= header_length:
                        print("Received:", message[0:header_length], message[header_length:])
                        self.encryption.log("Received additional rcpt in data.")
                        self.encryption.log(f"RCPT Request: {message[0:header_length]} {message[header_length:]}")
                        self._module_processor(message[0:header_length], message[header_length:])
                elif message == ".":
                    success = self._save_mail()
                    if success:
                        self._sub_state = ""
                        self._state = "helo"
                        self.encryption.log(f"Successful saving of mail for logged in user: {self._username}")
                        self._create_message(
                            self.return_codes.code_sort("250", self._state, "Requested mail action okay, completed"))
                else:
                    if self._sub_state == "subject":
                        self._data_subject += message
                        self.encryption.log("Received subject line. Subject line saved.")
                        self.encryption.log("Sub state set to: body")
                        self._sub_state = "body"
                    elif self._sub_state == "body":
                        self._data_body += message
                        self.encryption.log("Received more data for body. Data appended.")
                    else:
                        print("Error, there has been state mismanagement.")
                        self.encryption.log("Error, there has been state mismanagement during: _process_response.")
                        self._create_message(self.return_codes.code_sort("451", self._state, ""))
                        self._state = "quit"
                        self.close()
            # check to see how it is formatted
            else:
                if len(message) >= header_length:
                    if "logn".lower() in message[0:header_length]:
                        self.encryption.log(f"Received: {message[0:header_length]} *SENSITIVE DATA*")
                    else:
                        self.encryption.log(f"Received: {message[0:header_length]} {message[header_length:]}")
                    print("Received:", message[0:header_length], message[header_length:])
                    self._module_processor(message[0:header_length], message[header_length:])

    def _save_mail(self):
        """
        Takes the saved information from the data state and encrypts it. It then grabs checks for a json file, if not
        found it will create a new one. Once found or created it will load the file into memory. It will then append
        onto the file the latest email and save the file.
        :return:
        """
        _new_data = {}
        # Date time is grabbed and stored to ensure that users do not have different times if many are sent the email.
        _current_dt = datetime.now().strftime("%Y-%m-%d %H-%M-%S")
        _recipients = self._receipt_list
        # Data encryption
        encrypted_recipients = smtp_server_encryption.data_caesar_cipher_encrypt(str(self._receipt_list),
                                                                                 self._base_key)
        encrypted_current_dt = smtp_server_encryption.data_caesar_cipher_encrypt(_current_dt, self._base_key)
        encrypted_flag = smtp_server_encryption.data_caesar_cipher_encrypt(self._file_flag, self._base_key)
        encrypted_mail_from_domain = smtp_server_encryption.data_caesar_cipher_encrypt(self._mail_from_domain,
                                                                                       self._base_key)
        encrypted_data_subject = smtp_server_encryption.data_caesar_cipher_encrypt(self._data_subject, self._base_key)
        encrypted_data_body = smtp_server_encryption.data_caesar_cipher_encrypt(self._data_body, self._base_key)

        # Dictionary preparation of new encrypted data.
        _new_data['MAIL'] = []
        _new_data['MAIL'].append({
            'TimeDate:': encrypted_current_dt,
            'FLAG:': encrypted_flag,
            'From:': encrypted_mail_from_domain,
            'To:': encrypted_recipients,
            'Subject': encrypted_data_subject,
            'Body:': encrypted_data_body
        })
        # Once data has been prepared.
        for recipient in _recipients:
            try:
                # Set file path
                _recipient_folder = recipient.split("@")[0]
                _location_temp = [f"Server\\Users\\{_recipient_folder}\\emails.json"]
                _location = remove_space(''.join(_location_temp))
                # Create email file is none found.
                if path.exists(_location) != 1:
                    with open(_location, "w+") as file_check:
                        _base_data = {0: [recipient]}
                        json.dump(_base_data, file_check, indent=1)
                # Get file data currently stored
                with open(_location, "r") as f:
                    _file_data = json.loads(f.read())
                key = int(max(k for k, v in _file_data.items()))
                key += 1
                _file_data[key] = _new_data
                with open(_location, 'w+', encoding='utf-8') as f:
                    json.dump(_file_data, f, indent=1)
            except (NameError, ValueError, TypeError):
                return False
        return True

    def _domain_validation(self, message):
        """
        Domain validation uses a combination of regex and manual checking place of regex (my mind was melting)
        to validate a domain as being formatted correctly. Validate domain does not contact external services to
        perform any other validation.
        :param message: string, domain for validation
        :return: string, domain or "bad domain" AND int, 1 or 0 for success/fail.
        """
        __is_valid_domain = False
        _valid_2nd_half = False
        _valid_1st_half = False
        _hash_present = False
        _fail = False  # By default a fail
        try:
            _domain = remove_space(message)
            _domain_temp = _domain
            if len(message) < 3:
                return "bad domain", 0
            else:
                if ']' in _domain:
                    _domain_split = _domain.split("]")
                    _domain_1st = _domain_split[0][1:].split('.')
                    for i in _domain_1st:
                        v = int(i)
                        if v > 255 or v < 0:
                            _fail = True
                    if not _fail:
                        _valid_1st_half = 1

                _hash_position = _domain.find('#')
                if _hash_position != -1:
                    _hash_present = True
                    _domain_2nd = _domain[_hash_position + 1:]
                    useless, _valid_2nd_half = self._domain_validation(_domain_2nd)
                    if not _valid_1st_half and _hash_position >= 0:
                        _domain_temp = _domain_2nd
                if _hash_present:
                    if _valid_1st_half and _valid_2nd_half:
                        return _domain, 1
                elif _valid_1st_half:
                    return _domain, 1
                elif _hash_position != -1:
                    if _valid_2nd_half:
                        return _domain, 1

                if len(_domain) > 2:  # Length check and  domain validity check
                    regex_test = re.match(r'(([\da-zA-Z])([\w-]{,62}).){,127}(([\da-zA-Z])[\w-]{,61})?([\da-zA-Z].'
                                          r'((xn--[a-zA-Z\d]+)|([a-zA-Z\d]{2,})))', _domain_temp)
                    if regex_test is not None:
                        if _domain in self._reserved_domains:
                            __is_valid_domain = False
                        else:
                            __is_valid_domain = True
                    if __is_valid_domain:
                        return _domain, 1
                    else:
                        return "bad domain", 0
                else:
                    return "bad domain", 0
        except (NameError, ValueError):
            self._create_message(self.return_codes.code_sort("471", self._state, ""))
            return "error", -1

    def email_validation(self, message, state):
        """
        Email validation is intended to check the first half of an email for validity after splitting away
        any extras from data input from the client depending on the state.
        :param message: string, incoming message from the client.
        :param state: string, current client state.
        :return: bool, True for success, False for failure.
        """
        layout = 0
        if state == "mailprocessing" or state == "logincomplete":
            if "from:" in message.lower() and "@" in message:
                layout = 1
        elif state == "rcpt" or state == "mailfromcomplete" or state == "data" or state == "rcptcomplete":
            if "to:" in message.lower() and "@" in message:
                layout = 1
        else:
            self._create_message(self.return_codes.code_sort("503", self._state, ""))
            return "error", False
        if layout == 1:
            _no_space = remove_space(message)
            _whole_email = _no_space.split(":")[1]
            _email_at_split = _whole_email.split("@")
            _email = _email_at_split[0]
            _domain = _email_at_split[1]

            # Validity must be proved, false by default.
            _is_valid_email = False
            if len(message) >= 3:
                _regex_test = re.match(r'^\w+([\\.-]?\w+)', _email)
                if _regex_test is not None:
                    domain, outcome = self._domain_validation(_domain)
                    if outcome == 1:
                        _is_valid_email = True
            if _is_valid_email:
                return _whole_email, True
            else:
                self._create_message(self.return_codes.code_sort("553", self._state, "Bad Email or no email."))
                return "bad email", False
        else:
            self._create_message(self.return_codes.code_sort("501", self._state, ""))
            return "bad email", False

    def _negotiation(self, message):
        """
        Negotiation is called upon receiving a NGTN from the client, it responds by generating available encryption
        options and exchanging them. Upon receiving a choice from the client it will save the selected choice and await
        the first common + secret key mix. After receiving the client mix it sends out it's own mix,
        sets the key appropriately and enables encryption.
        :param message: string, incoming message from the client.
        :return: bool, False for failure, True for success.
        """
        # If it's the start of negotiation, generate keys
        if self._sub_state == "":
            methods = self.encryption.generate_available_methods()
            # If generate_available_methods returns -1 then it cannot find any available encryption options
            if -1 in methods:
                self._create_message(self.return_codes.code_sort("471", self._state, "No encryption available, "
                                                                                     "killing connection, sorry."))
                self.encryption.log("State set to: quit")
                self._state = "quit"
                self.close()
            else:
                # Send client list of available encryption methods
                message = "NGN METHODS AVAILABLE:"
                methods_string = ''.join(methods)
                final_value = " ".join((message, methods_string))
                self._create_message(final_value)
                self.encryption.log("Sub-State set to: method received")
                self._sub_state = "method received"

        # Set chosen encryption method and output to server
        elif self._sub_state == "method received":
            if ' ' in message:
                space_split = message.split(' ')
                message = space_split[1]
            if message in self.encryption.get_methods():
                self.encryption.set_method(message)
                self._create_message(
                    self.return_codes.code_sort("250", self._state, f"Method has been set to {message}"))
                self.encryption.log("Sub-State set to: method selected")
                self._sub_state = "method selected"

        # Once method is selected, send common mix for key exchange and
        # set server encryption key with received client mix.
        elif self._sub_state == "method selected":
            self.encryption.generate_common_mix()
            if " COMMON MIX:" in message:
                values = message.split("COMMON MIX:")
                self.encryption.generate_shared_secret(values[1])
                values = ["NGN COMMON MIX:", str(self.encryption.get_common_mix())]
                self._create_message(''.join(values))
                self._sub_state = ""
                self.encryption.log("Sub-State set to: ''")
                return True
            else:
                self._create_message(self.return_codes.code_sort("501", self._state, ""))
                return False

    def _login_user(self, input_message):
        """
        Compares username and hash(password+dob) with stored records.
        :param input_message: string, username, password, dateofbirth
        """
        if " " in input_message and len(input_message) >= 4:
            message = input_message.split(" ")
            if len(message) >= 4:
                self._input_username = message[1]
                if path.exists("Server\\UandP.txt") == 1:
                    f = open("Server\\UandP.txt", "r")
                    if self._logged_in != 1 and self._login_attempts <= 10:
                        for line in f:
                            line_found = line.split(" ")
                            file_username = line_found[0]
                            if self._logged_in != 1:
                                if self._input_username == file_username:
                                    file_hash = line_found[1]
                                    values = [message[2], message[3]]
                                    input_hash = self.encryption.hash_input(''.join(values))
                                    if input_hash in file_hash:
                                        self._username = self._input_username
                                        self.encryption.set_user(self._username)
                                        self.encryption.log(f"{self._username} has successfully logged in.")
                                        self._state = "logincomplete"
                                        self.encryption.log("State set to: logincomplete")
                                        self._logged_in = 1
                                        self._create_message(self.return_codes.code_sort
                                                             ("250", self._state, " You have successfully logged in."))
                                        break
                        # If user still not logged in after loop through the file
                        if self._logged_in != 1:
                            self._create_message(self.return_codes.code_sort("530", self._state,
                                                                             "Invalid credentials."))
                            self._login_attempts += 1
                    else:
                        self._create_message(self.return_codes.code_sort
                                             ("530", self._state, "You have attempted login > 10 times and failed."))
                        print("The user attempted login 10 times without success. Killing connection.")
                        f.close()
                        self._state = "quit"
                        self.encryption.log("State set to: quit")
                else:
                    self._create_message(self.return_codes.code_sort("451", self._state, ""))
                    self.encryption.log("Program closing, could not locate user names and passwords file.")
                    print("Error. Username and passwords file doesn't exist.")
                    print("Closing program and killing connection.")
                    self.encryption.log("State set to: quit")
                    self._state = "quit"
                    self.close()

            else:
                self._create_message(self.return_codes.code_sort("501", self._state, " Too few arguments."))

        else:
            self._create_message(self.return_codes.code_sort("501", self._state, ""))
            print("Received LOGIN formatted incorrectly.")
            self.encryption.log("Received LOGN formatted incorrectly.")

    def _module_processor(self, command, message):
        command = command.lower()

        # Negotiation != data state error
        if command == "ngtn" and self._state != "data":
            self.encryption.disable()
            self._negotiated = self._negotiation(message)
            if self._negotiated:
                self._create_message("250 OK; Negotiation completed.")
                self.encryption.enable()
                if self._state == "start":
                    self._state = "helo"
                    self.encryption.log("State set to: helo")

        # Negotiation in data state (in error)
        elif command == "ngtn" and self._state == "data":
            self._create_message(self.return_codes.code_sort("503", self._state, "You are in the incorrect state."))

        # HELO correct state
        elif command == "helo" and self._state == "helo":
            self._sender_domain, outcome = self._domain_validation(message)
            if outcome == 1:
                self._create_message(self.return_codes.code_sort("250", self._state, self._my_domain))
                if self._logged_in == 0:
                    self._state = "login"
                    self.encryption.log("State set to: login")
                elif self._logged_in == 1:
                    self._state = "logincomplete"
                    self.encryption.log("State set to: logincomplete")
            elif outcome == 0:
                self._create_message(self.return_codes.code_sort("501", self._state, " Invalid domain"))

        # HELO in-correct state
        elif command == "helo" and self._state != "helo":
            self._create_message(self.return_codes.code_sort("503", self._state, "You are in the incorrect state. "
                                                                                 "Ensure negotiation is completed."))
            print("Received a HELO out of state")

        # LOGIN correct state
        elif command == "logn" and self._state == "login":
            self._login_user(message)

        # LOGIN in-correct state
        elif command == "logn" and self._state != "login":
            if self._logged_in == 1:
                self._create_message(self.return_codes.code_sort("503", self._state, "You are already logged in."))
                print("Received a LOGN though user already logged in.")
            elif self._logged_in == 0:
                self._create_message(self.return_codes.code_sort("503", self._state, "You are in the incorrect state."))

        # MAIL correct state
        elif command == "mail" and (self._state == "logincomplete" or self._state == "mailprocessing"):
            if self._logged_in == 1:
                self._state = "mailprocessing"
                self.encryption.log("State set to: mailprocessing")
                self._mail_from_domain, success = self.email_validation(message, self._state)
                if success:
                    self._state = "mailfromcomplete"
                    self.encryption.log("State set to: mailfromcomplete")
                    self._create_message(self.return_codes.code_sort("250", self._state,
                                                                     "Requested mail action okay, completed"))
            elif self._logged_in == 0:
                self._create_message(self.return_codes.code_sort("503", self._state, "You are not logged in."))
                print("Received a MAIL. In state = True. Logged in = false.")
                self.encryption.log("Received a MAIL. In state = True. Logged in = false.")
            else:
                self._create_message(self.return_codes.code_sort("554", self._state, ""))
                self._create_message(self.return_codes.code_sort("221", self._state, self._my_domain))
                self.encryption.log("State set to: quit")
                self._state = "quit"

        # MAIL in-correct state
        elif command == "mail" and self._state != "mailprocessing" and self._state != "logincomplete":
            if self._logged_in == 1:
                self._create_message(self.return_codes.code_sort("503", self._state, "You are in the incorrect state."))
                print("Received a MAIL. In state = false. Logged in = true.")
                self.encryption.log("Received a MAIL. In state = false. Logged in = true.")
            elif self._logged_in == 0:
                self._create_message(self.return_codes.code_sort("503", self._state, "You are not logged in."))
                print("Received a MAIL. In state = false. Logged in = false.")
                self.encryption.log("Received a MAIL. In state = false. Logged in = false.")
            else:
                self._create_message(self.return_codes.code_sort("471", self._state, "Unknown fatal error."))
                self.encryption.log("Sending: 471 Server error, you broke the server")
                self._create_message(self.return_codes.code_sort("554", self._state, ""))
                self._create_message(self.return_codes.code_sort("221", self._state, self._my_domain))
                self._state = "quit"
                self.encryption.log("State set to: quit")

        # RCPT correct state
        elif command == "rcpt" and (self._state == "mailfromcomplete" or
                                    self._state == "rcpt" or self._state == "data"):
            self.encryption.log("Received a RCPT.")
            present = False
            _returned_domain, success = self.email_validation(message, self._state)
            if success:
                _target_user_domain = _returned_domain.split('@')
                if remove_space(_target_user_domain[1]) in self._my_domain:
                    if remove_space(_target_user_domain[0]) in self._user_list:
                        for item in self._receipt_list:
                            if remove_space(_returned_domain) in item:
                                self._create_message(self.return_codes.code_sort
                                                     ("550", self._state, "mailbox unavailable, already a recipient"))
                                self.encryption.log("Sent: 550 Requested action not taken: mailbox "
                                                    "unavailable, already a recipient")
                                present = True
                                break
                        if not present:
                            self.encryption.log(f"Recipient added: {_returned_domain}")
                            self._receipt_list.append(_returned_domain)
                            self._create_message(self.return_codes.code_sort
                                                 ("250", self._state, "Recipient added, okay."))
                            if self._state == "data":
                                self._state = "data"
                            else:
                                self._state = "rcpt"
                                self.encryption.log("Set state to: rcpt")
                    else:
                        self._create_message(self.return_codes.code_sort("450", self._state, ""))
                else:
                    self._create_message(self.return_codes.code_sort("251", self._state,
                                                                     f"User not local; will forward to "
                                                                     f"{_target_user_domain[1]}"))

        # RCPT in-correct state
        elif command == "rcpt" and (self._state != "mailfromcomplete" and self._state != "rcpt"):
            self._create_message(self.return_codes.code_sort("503", self._state, "You are in the incorrect state."))
            self.encryption.log("Received a RCPT out of state.")
            print("Received a RCPT out of state.")

        # DATA correct state
        elif command == "data" and self._state == "rcpt":
            self._create_message(self.return_codes.code_sort("354", self._state, "Entering DATA State.\r\nThe first "
                                                                                 "line you enter will be the subject."))
            self.encryption.log("Received a DATA. Entering data state.")
            self._state = "data"
            self._sub_state = "subject"
            self.encryption.log("Sub-State set to: subject")
            # should contain "<CRLF>.<CRLF>" to end data entry.

        # DATA in-correct state
        elif command == "data" and self._state != "rcpt":
            self._create_message(self.return_codes.code_sort("503", self._state, "You are in the incorrect state."))
            self.encryption.log("Received a data out of state.")
            print("Received a data out of state.")

        # DELETE Users entire mailbox
        elif command == "dltm" and self._state != "data" and self._logged_in == 1:
            try:
                _location_temp = [f"Server\\Users\\{self._username}\\emails.json"]
                _location = remove_space(''.join(_location_temp))
                if path.exists(_location):
                    _file = pathlib.Path(_location)
                    _file.unlink()
                    self.encryption.log(f"Deleted {self._username} entire mailbox.")
                    self._create_message(self.return_codes.code_sort("250", self._state, "Entire mailbox deleted."))
                else:
                    self._create_message(self.return_codes.code_sort("503", self._state, "Couldn't find the mailbox."))
                    self.encryption.log("Couldn't find the mailbox for deletion.")
            except (NameError, ValueError, TypeError):
                self._create_message(self.return_codes.code_sort("471", self._state, "Couldn't delete mailbox."))

        # DELETE Users entire mailbox, wrong state or not logged in.
        elif command == "dltm":
            if self._logged_in == 0:
                self._create_message(self.return_codes.code_sort("503", self._state, "Please login first."))
                self.encryption.log("User tried to access dltm (delete mailbox) before logging in.")
            elif self._state == "data":
                self._create_message(self.return_codes.code_sort("503", self._state, "You cannot do this in data."))
                self.encryption.log("User tried to access dltm (delete mailbox) from DATA.")

        # NOOP correct state
        elif command == "noop":
            self._create_message(self.return_codes.code_sort("250", self._state,
                                                             "Requested mail action okay; completed."))
        # HELP
        elif command == "help":
            self._create_message(self.return_codes.code_sort("214", self._state, ""))

        # VERIFY - Verify that a user exists and get mailbox.
        elif command == "vrfy" and self._state != "data":
            _matches = []
            for value in self._user_list:
                if remove_space(message) in value:
                    _matches.append(value + "@" + self._my_domain)
            if len(_matches) > 1:
                self._create_message(self.return_codes.code_sort("553", self._state, "User ambiguous."))
            elif len(_matches) == 1:
                self._create_message(self.return_codes.code_sort("250", self._state, f"User found: {_matches}"))
            elif len(_matches) == 0:
                self._create_message(self.return_codes.code_sort("550", self._state, " User not found"))
            else:
                self._create_message(self.return_codes.code_sort("501", self._state, ""))

        # EXPAND - Expands a group or list of users.
        elif command == "expn" and self._state != "data":
            _match = ""
            _members = []
            self.encryption.log("Searching groups as requested.")
            for value in self._group_list:
                if remove_space(message.lower()) in value:
                    _match = value
                    if path.exists("Server\\Groups\\Groups.txt") == 1:
                        with open("Server\\Groups\\Groups.txt", "r") as f:
                            for line in f:
                                line_found = line.split(":")
                                if line_found[0] == value:
                                    _members = line_found[1:(len(line_found) - 1)]
                                    break
                if len(_members) != 0:
                    for member in _members:
                        member += "@" + self._my_domain
                    self._create_message(self.return_codes.code_sort
                                         ("250", self._state, "Requested mail action okay; completed."))
                    self._create_message(f"250 Group: {_match} Members: {_members}")
                    self.encryption.log("Sending: 250 Requested mail action okay; completed.")
                    self.encryption.log("Found matches to EXPN, sending.")

        # RESET - Re-initialises program.
        elif command == "rset":
            self.encryption.log("RSET Called by user. Starting RSET.")
            success = self._my_initialise()
            if success:
                self._create_message(self.return_codes.code_sort("250", self._state, "RSET Completed."))
                self.encryption.log("Successfully RSET.")
            else:
                self.encryption.log("RSET Failed, closing service.")
                self._create_message(self.return_codes.code_sort("471", self._state, "RSET failed, closing service."))
                self._state = "quit"
                self.close()

        # QUIT - closes thread.
        elif command == "quit" or self._state == "quit":
            self._create_message("250 OK; QUITTING.")
            self.encryption.log("Received a QUIT. Quitting")
            print("Received a QUIT.")
            self._state = "quit"
            self.close()

        # TURN - optional
        elif command == "turn":
            self._create_message(self.return_codes.code_sort("502", self._state, ""))

        # HASH - Only available to admin
        elif command == "hash" and self._logged_in == 1 and self._username == "admin":
            value = self.encryption.hash_password(message)  # Message is the position of line to be hashed.
            if value == 1:
                self._create_message(self.return_codes.code_sort("250", self._state, ""))
            elif value == 0:
                self._create_message(
                    self.return_codes.code_sort("471", self._state, "No username + password file was found."))
            elif value == -1:
                self._create_message(
                    self.return_codes.code_sort("471", self._state, "General unknown error with hashing."))

        # Hash not admin
        elif command == "hash" and (self._logged_in != 1 or self._username != "admin"):
            self._create_message(self.return_codes.code_sort("503", self._state, "You must be logged in as an admin to "
                                                                                 "access this command."))
        # RFC 5321 Considerations
        elif command == "ehlo" and self._state == "helo":
            self._create_message(self.return_codes.code_sort("504", self._state, ""))
            self.encryption.log("EHLO Not supported.")

        # Handles deleting of individual mail via subject
        elif command == "dlet" and self._state != "data" and self._logged_in == 3:
            # FIXME: Disabled at the moment as non-functioning, set "self._logged_in == 1:" instead of 3 for run.
            # FIXME: This is here to help me understand the formatting I did whilst I search the json file.
            #_ new_data['MAIL'] = []
            #_ new_data['MAIL'].append({
            #    'TimeDate:': encrypted_current_dt,
            #    'FLAG:': encrypted_flag,
            #    'From:': encrypted_mail_from_domain,
            #    'To:': encrypted_recipients,
            #    'Subject': encrypted_data_subject,
            #    'Body:': encrypted_data_body
            #  })
            try:
                _location_temp = [f"Server\\Users\\{self._username}\\emails.json"]
                _location = remove_space(''.join(_location_temp))
                if path.exists(_location):
                    # Get file data currently stored
                    with open(_location, "r") as f:
                        _file_data = json.loads(f.read())

                    # Alter the file in memory
                    for email in _file_data:
                        if message in email:
                            # delete email
                            print("temp under construction")

                    # Write back to file new updated data
                    with open(_location, 'w+', encoding='utf-8') as f:
                        json.dump(_file_data, f, indent=1)
            except (NameError, ValueError, TypeError):
                return False
            return True  # TODO Change to appropriate return message and log.
        else:
            self._create_message(self.return_codes.code_sort("500", self._state, ""))
