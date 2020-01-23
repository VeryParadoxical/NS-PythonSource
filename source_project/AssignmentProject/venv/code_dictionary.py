import smtp_server_encryption


class ReturnCodeDictionary:
    def __init__(self):
        self.encryption = smtp_server_encryption.NWSEncryption()
        self._state = ""
        self._code = ""
        self._additional_information = ""

    def _help(self):
        """
        Takes the current state and passes out the relevant help message for that state.
        :return: string, returns a state dependant help message.
        """
        _message = f'{self._code} This server supports the following commands:' \
                   f'\r\nNGTN' \
                   f'\r\nHELO <DOMAIN>' \
                   f'\r\nLOGN USERNAME PASSWORD DATEOFBIRTH' \
                   f'\r\nMAIL FROM: <USER@DOMAIN>' \
                   f'\r\nRCPT TO: <USER@DOMAIN>' \
                   f'\r\nDATA' \
                   f'\r\nVRFY <USER>' \
                   f'\r\nRSET' \
                   f'\r\nEXPN <USER>' \
                   f'\r\nDLTM' \
                   f'\r\nNOOP' \
                   f'\r\nQUIT' \
                   f'\r\nNOTE: Not all commands may be currently accessible from your position.' \
                   f'\r\n\r\nHere is an error message for your current state:\r\n'
        if self._state == "start":
            self._message = f"{self._code} To start negotiation please enter: NGTN\r\nAfter please select an " \
                            f"encryption method from those shown above." \
                            f"\r\nAfter the program will produce keys and conduct a " \
                            "key exchange.\r\nAll further communications from that point are encrypted.\r\n" \
                            "You can renegotiate at any time excluding the data state.\r\n"

        elif self._state == "helo":
            self._message = f"{self._code} HELO HELP: To say hello to the mail server please type: HELO <domain>"

        elif self._state == "login":
            self._message = f"{self._code} LOGIN HELP: To Login please format your command as follows: " \
                            f"LOGN username password DateOfBirth"

        elif self._state == "logincomplete" or self._state == "mailprocessing":
            self._message = f"{self._code} MAIL HELP: To access the MAIL command please format your " \
                            f"message as follows: MAIL from: <domain>"

        elif self._state == "rcpt" or self._state == "mailfromcomplete":
            self._message = f"{self._code} RCPT HELP: To access the receipt " \
                            f"command please enter: rcpt to: <domain>\r\nYou are " \
                            f"able to do this command multiple times to add more recipients."

        elif self._state == "data" or self._state == "rcptadded":
            self._message = f"{self._code} DATA HELP: Formatting rules for data are as follows:\r\n" \
                            "To enter another recipient enter: RCPT TO: <domain>\r\n" \
                            "To enter your data just type it in and hit enter. No brackets required or anything.\r\n" \
                            "You can send your data in multiple messages and " \
                            "it will be combined before being saved.\r\n" \
                            "To stop entering data please enter <CLRF>.<CLRF> \r\n(just a full stop on it's own)"

        elif self._state == "negotiation":
            self._message = f"{self._code} You must select an encryption method that is shared by both the client " \
                            f"and server. " \
                            "Please select an option."

        elif self._state == "ce":
            self._message = f"{self._code} No idea what goes here, connection established."

        elif self._state == "quit":
            self._message = f"{self._code} The program is exiting, good bye."

        else:
            self._message = ("504 Command parameter is not implemented. \r\n"
                             "Cannot find the help message for the current state.")

        return _message + self._message

    def _101_code(self):
        """
        Method that returns a specific error message with attached information if needed.
        :return: string, returns error code.
        """
        # TODO LoggingHere
        self._message = "101 The server was unable to connect."
        return self._message

    def _111_code(self):
        """
        Method that returns a specific error message with attached information if needed.
        :return: string, returns error code.
        """
        # TODO LoggingHere
        self._message = "111 Connection refused or inability to open an SMTP Stream."
        return self._message

    def _200_code(self):
        """
        Method that returns a specific error message with attached information if needed.
        :return: string, returns error code.
        """
        # TODO LoggingHere
        value = self._help()
        message = ["200 Non standard success response [rfc876]: ", value]  # Pass in success msg
        self._message = ''.join(message)
        return self._message

    def _211_code(self):
        """
        Method that returns a specific error message with attached information if needed.
        This method makes a call to the help dictionary as it requires the help information.
        :return: string, returns error code.
        """
        # TODO LoggingHere
        value = self._help()
        message = ["211 System status message or help reply.\r\n", value]
        self._message = ''.join(message)
        return self._message

    def _214_code(self):
        """
        Method that returns a specific error message with attached information if needed.
        :return: string, returns error code.
        This method makes a call to the help dictionary as it requires the help information.
        """
        # TODO LoggingHere
        self._message = self._help()
        return self._message

    def _220_code(self):
        """
        Method that returns a specific error message with attached information if needed.
        :return: string, returns error code.
        """
        # TODO LoggingHere
        message = ["220 <", self._additional_information, "> Server is ready"]
        self._message = ''.join(message)
        return self._message

    def _221_code(self):
        """
        Method that returns a specific error message with attached information if needed.
        :return: string, returns error code.
        """
        # TODO LoggingHere
        message = ["221 <", self._additional_information,
                   "> server is closing its transmission channel."]  # Pass in domain
        self._message = ''.join(message)
        return self._message

    def _250_code(self):
        """
        Method that returns a specific error message with attached information if needed.
        :return: string, returns error code.
        """
        # TODO LoggingHere
        message = ["250 ", self._additional_information]
        self._message = ''.join(message)
        return self._message

    def _251_code(self):
        """
        Method that returns a specific error message with attached information if needed.
        :return: string, returns error code.
        """
        # TODO LoggingHere
        message = ["251 User not local, will forward to <", self._additional_information, ">."]  # Pass in forward path.
        self._message = ''.join(message)
        return self._message

    def _252_code(self):
        """
        Method that returns a specific error message with attached information if needed.
        :return: string, returns error code.
        """
        # TODO LoggingHere
        self._message = "252 Cannot verify the user, will try to deliver message."
        return self._message

    def _354_code(self):
        """
        Method that returns a specific error message with attached information if needed.
        :return: string, returns error code.
        """
        # TODO LoggingHere
        self._message = f"354 Start mail input; end with <CRLF>.<CRLF>\r{self._additional_information}"
        return self._message

    def _420_code(self):
        """
        Method that returns a specific error message with attached information if needed.
        :return: string, returns error code.
        """
        # TODO LoggingHere
        self._message = "420 Connection timed out."
        return self._message

    def _421_code(self):
        """
        Method that returns a specific error message with attached information if needed.
        :return: string, returns error code.
        """
        # TODO LoggingHere
        message = ["421 <", self._additional_information, "> Service not available, closing transmission channel."]
        self._message = ''.join(message)
        return self._message

    def _422_code(self):
        """
        Method that returns a specific error message with attached information if needed.
        :return: string, returns error code.
        """
        # TODO LoggingHere
        self._message = "422 The recipients mailbox has exceeded its storage limit."

        return self._message

    def _431_code(self):
        """
        Method that returns a specific error message with attached information if needed.
        :return: string, returns error code.
        """
        # TODO LoggingHere
        self._message = "431 Not enough disk space."
        return self._message

    def _432_code(self):
        """
        Method that returns a specific error message with attached information if needed.
        :return: string, returns error code.
        """
        # TODO LoggingHere
        self._message = "432 Recipients incoming mail queue has been stopped."
        return self._message

    def _441_code(self):
        """
        Method that returns a specific error message with attached information if needed.
        :return: string, returns error code.
        """
        # TODO LoggingHere
        self._message = "441 The recipients server is not responding."
        return self._message

    def _442_code(self):
        """
        Method that returns a specific error message with attached information if needed.
        :return: string, returns error code.
        """
        # TODO LoggingHere
        self._message = "442 The connection was dropped during the transmission."
        return self._message

    def _446_code(self):
        """
        Method that returns a specific error message with attached information if needed.
        :return: string, returns error code.
        """
        # TODO LoggingHere
        self._message = "446 The maximum hop count was exceeded for the message."
        return self._message

    def _447_code(self):
        """
        Method that returns a specific error message with attached information if needed.
        :return: string, returns error code.
        """
        # TODO LoggingHere
        self._message = "447 Message timed out because of issues concerning the incoming server."
        return self._message

    def _449_code(self):
        """
        Method that returns a specific error message with attached information if needed.
        :return: string, returns error code.
        """
        # TODO LoggingHere
        self._message = "449 Routing error."
        return self._message

    def _450_code(self):
        """
        Method that returns a specific error message with attached information if needed.
        :return: string, returns error code.
        """
        # TODO LoggingHere
        self._message = "450 Requested mail action not taken: mailbox unavailable."  # Mailbox is busy.
        return self._message

    def _451_code(self):
        """
        Method that returns a specific error message with attached information if needed.
        :return: string, returns error code.
        """
        # TODO LoggingHere
        self._message = "451 Requested action aborted: error in processing."
        return self._message

    def _452_code(self):
        """
        Method that returns a specific error message with attached information if needed.
        :return: string, returns error code.
        """
        # TODO LoggingHere
        self._message = "452 Requested action not taken: mailbox name not allowed."
        return self._message

    def _471_code(self):
        """
        Method that returns a specific error message with attached information if needed.
        :return: string, returns error code.
        """
        # TODO LoggingHere
        message = ["471 Email server error. ", self._additional_information]
        self._message = ''.join(message)
        return self._message

    def _500_code(self):
        """
        Method that returns a specific error message with attached information if needed.
        :return: string, returns error code.
        """
        # TODO LoggingHere
        self._message = "500 Syntax error, command unrecognised."
        return self._message

    def _501_code(self):
        """
        Method that returns a specific error message with attached information if needed.
        :return: string, returns error code.
        """
        # TODO LoggingHere
        self._message = "501 Syntax error in parameters or arguments."
        return self._message

    def _502_code(self):
        """
        Method that returns a specific error message with attached information if needed.
        :return: string, returns error code.
        """
        self._message = "502 Command not implemented."
        return self._message

    def _503_code(self):
        # TODO LoggingHere
        message = ["503 Bad sequence of commands, or requires authentication. ", self._additional_information]
        self._message = ''.join(message)
        return self._message

    def _504_code(self):
        """
        Method that returns a specific error message with attached information if needed.
        :return: string, returns error code.
        """
        # TODO LoggingHere
        self._message = "504 Command parameter is not implemented."
        return self._message

    def _510_code(self):
        """
        Method that returns a specific error message with attached information if needed.
        :return: string, returns error code.
        """
        # TODO LoggingHere
        self._message = "510 Bad email address. One of the addresses entered does not exist."
        return self._message

    def _511_code(self):
        """
        Method that returns a specific error message with attached information if needed.
        :return: string, returns error code.
        """
        # TODO LoggingHere
        self._message = "511 Bad email address. One of the addresses entered does not exist."
        return self._message

    def _512_code(self):
        """
        Method that returns a specific error message with attached information if needed.
        :return: string, returns error code.
        """
        # TODO LoggingHere
        self._message = "512 Host server for recipients domain name cannot be found in DNS."
        return self._message

    def _513_code(self):
        """
        Method that returns a specific error message with attached information if needed.
        :return: string, returns error code.
        """
        # TODO LoggingHere
        self._message = "513 Address type is incorrect."
        return self._message

    def _521_code(self):
        """
        Method that returns a specific error message with attached information if needed.
        :return: string, returns error code.
        """
        # TODO LoggingHere
        message = ["521", self._additional_information, " does not accept mail [rfc1846]"]  # Pass in domain
        self._message = ''.join(message)
        return self._message

    def _523_code(self):
        """
        Method that returns a specific error message with attached information if needed.
        :return: string, returns error code.
        """
        # TODO LoggingHere
        self._message = "523 Size of your mail exceeds the server limits."
        return self._message

    def _530_code(self):
        """
        Method that returns a specific error message with attached information if needed.
        :return: string, returns error code.
        """
        # TODO LoggingHere
        message = ["530 Authentication problem. ", self._additional_information]
        self._message = ''.join(message)
        return self._message

    def _541_code(self):
        """
        Method that returns a specific error message with attached information if needed.
        :return: string, returns error code.
        """
        # TODO LoggingHere
        self._message = "541 The recipient address rejected your message."
        return self._message

    def _550_code(self):
        """
        Method that returns a specific error message with attached information if needed.
        :return: string, returns error code.
        """
        # TODO LoggingHere
        message = ["550 Requested action not taken:", self._additional_information,
                   "."]  # Pass in reason for action not being taken (mailbox not found, no access)
        self._message = ''.join(message)
        return self._message

    def _551_code(self):
        """
        Method that returns a specific error message with attached information if needed.
        :return: string, returns error code.
        """
        # TODO LoggingHere
        message = ["551 User not local; please try <", self._additional_information, ">"]  # Pass in forward path
        self._message = ''.join(message)
        return self._message

    def _552_code(self):
        """
        Method that returns a specific error message with attached information if needed.
        :return: string, returns error code.
        """
        # TODO LoggingHere
        self._message = "552 Requested mail action aborted: exceeded storage allocation."
        return self._message

    def _553_code(self):
        """
        Method that returns a specific error message with attached information if needed.
        :return: string, returns error code.
        """
        # TODO LoggingHere
        message = ["553 Requested action not taken: ", self._additional_information]
        self._message = ''.join(message)
        return self._message

    def _554_code(self):
        """
        Method that returns a specific error message with attached information if needed.
        :return: string, returns error code.
        """
        # TODO LoggingHere
        self._message = "554 Transaction failed."
        return self._message

    def _informational_switch(self, code):
        """
        Switch designed to iterate through available codes searching for the correct code. If the code is not
        found in the switch it will return the value for the 503 error code as there has been an error. The
        method uses a form of python switch taking advantage of a dictionary and using pythons ability to
        execute statements via printing.
        :param code: string, should be a 3 digit error code. Immediately converted into an int.
        :return: string, returns a full error code message ready for output.
        """
        code_temp = int(code)
        switch = {
            101: self._101_code,
            111: self._111_code
        }
        code_execution = switch.get(code_temp, lambda: self._503_code())
        print(code_execution())
        return self._message

    def _successful_switch(self, code):
        """
        Switch designed to iterate through available codes searching for the correct code. If the code is not
        found in the switch it will return the value for the 503 error code as there has been an error. The
        method uses a form of python switch taking advantage of a dictionary and using pythons ability to
        execute statements via printing.
        :param code: string, should be a 3 digit error code. Immediately converted into an int.
        :return: string, returns a full error code message ready for output.
        """
        code_temp = int(code)
        switch = {
            200: self._200_code,
            211: self._211_code,
            214: self._214_code,
            220: self._220_code,
            221: self._221_code,
            250: self._250_code,
            251: self._251_code,
            252: self._252_code
        }
        code_execution = switch.get(code_temp, lambda: self._503_code())
        print(code_execution())
        return self._message

    def _redirection_switch(self, code):
        """
        Switch designed to iterate through available codes searching for the correct code. If the code is not
        found in the switch it will return the value for the 503 error code as there has been an error. The
        method uses a form of python switch taking advantage of a dictionary and using pythons ability to
        execute statements via printing.
        :param code: string, should be a 3 digit error code. Immediately converted into an int.
        :return: string, returns a full error code message ready for output.
        """
        code_temp = int(code)
        switch = {
            354: self._354_code
        }
        code_execution = switch.get(code_temp, lambda: self._503_code())
        print(code_execution())
        return self._message

    def _client_error_switch(self, code):
        """
        Switch designed to iterate through available codes searching for the correct code. If the code is not
        found in the switch it will return the value for the 503 error code as there has been an error. The
        method uses a form of python switch taking advantage of a dictionary and using pythons ability to
        execute statements via printing.
        :param code: string, should be a 3 digit error code. Immediately converted into an int.
        :return: string, returns a full error code message ready for output.
        """
        code_temp = int(code)
        switch = {
            420: self._420_code,
            421: self._421_code,
            422: self._422_code,
            431: self._431_code,
            432: self._432_code,
            441: self._441_code,
            442: self._442_code,
            446: self._446_code,
            447: self._447_code,
            449: self._449_code,
            450: self._450_code,
            451: self._451_code,
            452: self._452_code,
            471: self._471_code
        }
        code_execution = switch.get(code_temp, lambda: self._503_code())
        print(code_execution())
        return self._message

    def _server_error_switch(self, code):
        """
        Switch designed to iterate through available codes searching for the correct code. If the code is not
        found in the switch it will return the value for the 503 error code as there has been an error. The
        method uses a form of python switch taking advantage of a dictionary and using pythons ability to
        execute statements via printing.
        :param code: string, should be a 3 digit error code. Immediately converted into an int.
        :return: string, returns a full error code message ready for output.
        """
        code_temp = int(code)
        switch = {
            500: self._500_code,
            501: self._501_code,
            502: self._502_code,
            503: self._503_code,
            504: self._504_code,
            510: self._510_code,
            511: self._511_code,
            512: self._512_code,
            513: self._513_code,
            521: self._521_code,
            523: self._523_code,
            530: self._530_code,
            541: self._541_code,
            550: self._550_code,
            551: self._551_code,
            552: self._552_code,
            553: self._553_code,
            554: self._554_code
        }
        code_execution = switch.get(code_temp, lambda: self._503_code())
        print(code_execution())
        return self._message

    def code_sort(self, code, state, additional_information):
        """
        Acts as a sort of flow control determining which switch I should access for the correct error message
        dependant on which group of error message the code belongs to. Therefore reducing search time to find the
        code out of the long list of possible codes.
        1 = Informational - The request was received, continuing process
        2 = Successful - The request was successfully received, understood, and accepted.
        3 = Redirection - Further action needs to be taken in order to complete the request.
        4 = Client Error - The request contains bad syntax or cannot be fulfilled.
        5 = Server Error - The server failed to fulfill an apparently valid request.
        :param code: string, should be 3 numbers.
        :param state: string, should be the name of the current state.
        :param additional_information: string, any additional information required for the error code.
        :return: string, returns the complete error message ready for output.
        """
        self._state = state
        self._code = code
        self._additional_information = additional_information

        if code[0] == "1":
            value = self._informational_switch(code)
            return value
        elif code[0] == "2":
            value = self._successful_switch(code)
            return value
        elif code[0] == "3":
            value = self._redirection_switch(code)
            return value
        elif code[0] == "4":
            value = self._client_error_switch(code)
            return value
        elif code[0] == "5":
            value = self._server_error_switch(code)
            return value
        else:
            print("Status invalid.")
            return "Status invalid."
