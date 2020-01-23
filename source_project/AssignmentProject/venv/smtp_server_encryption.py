from os import path
import hashlib
from random import randint
from datetime import datetime


def data_caesar_cipher_encrypt(message, key) -> str:
    """
    Encrypts incoming data and returns encrypted data. This variant of the
    base method allows for external input of the key.
    :param message: Takes plain-text input.
    :param key: int, chosen data storage encryption key.
    :return: Should return encrypted data.
    """
    try:
        __encrypted = []
        for ch in message:
            __encrypted.append(chr(ord(ch) + key))
    except TypeError:
        return " "
    return ''.join(__encrypted)


def data_caesar_cipher_decrypt(message, key) -> str:
    """
    Decrypts an incoming message and returns plain-text. This variant of the
    base method allows for external input of the key.
    :param message: Encrypted data.
    :param key: int, chosen data storage encryption key.
    :return: Should return decrypted data as a single value.

    """
    try:
        __decrypted = []
        for ch in message:
            __decrypted.append(chr(ord(ch) - key))
    except TypeError:
        return ""
    return ''.join(__decrypted)


def get_date_time():
    _current_dt = datetime.now()
    _dt_organised = _current_dt.strftime("%Y-%m-%d %H-%M-%S")
    return _dt_organised


class NWSEncryption:
    def __init__(self):
        self._enabled = False
        # Add more methods below
        self._method = "caesar"

        # List all available encryption methods as shown below along with their status.
        self._caesar_available = True
        self._rsa_available = False

        self._alphabet = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789!£$%^&*()-+={}[]:;@'<,>.?/\\#"
        self._caesar_key = 1
        self._common_key = 7
        self._secret_key = 0
        self._common_mix = 0
        self._shared_secret = 0
        self._methods_available = []
        self._log_location = ""
        self._user = "Not logged in yet."
        self._base_key = 0

    def generate_available_methods(self):
        """
        Generates a list of all enabled encryption methods,
        if none then it returns a list containing only -1.
        :return: list of strings
        """
        self._methods_available = []
        if self._caesar_available:
            self._methods_available.append("caesar")
        if self._rsa_available:
            self._methods_available.append("rsa")
        if len(self._methods_available) == 0:
            self._enabled = False
            self._methods_available.append(-1)
        return self._methods_available

    def get_methods(self):
        """
        Used to get the available encryption methods as set during initialisation.
        :return: list of strings.
        """
        return self._methods_available

    def toggle_enable(self):
        """
        Accessor to enable/disable encryption.
        :return: Returns the status of the 'switch' for encryption.
        """
        self._enabled = not self._enabled
        return self._enabled

    def disable(self):
        """
        Similar to toggle_enable. Though specifically for disabling the encryption rather than toggling.
        """
        if self._enabled:
            self._enabled = False

    def enable(self):
        """
        Similar to toggle_enable. Though specifically for enabling the encryption rather than toggling.
        """
        if not self._enabled:
            self._enabled = True

    def set_base_key(self, key):
        self._base_key = key

    def set_user(self, user):
        self._user = user

    def set_caesar_key(self, key):
        """
        Accessor to set key for caesar cipher.
        :param key: int, key for cipher.
        :return: return 1 if successful, none if failed.
        """
        try:
            self._caesar_key = int(key)
        except TypeError:
            self._caesar_key = 10
            return None
        return 1

    def set_method(self, method):
        """
        Accessor to set the encryption method.
        :param method: encryption method of choice as string.
        """
        if method.lower() == "caesar":
            self._method = "caesar"
        else:
            self._method = None
            self.toggle_enable()

    def validate_choice(self, choice):
        """
        Used to easily check whether a user choice of encryption method is also found on this client
        prior to sending it to the server.
        :param choice: string, this is the encryption method
        :return: bool, true if it was found, false if not.
        """
        if choice in self._methods_available:
            return True
        else:
            return False

    def encrypt(self, message) -> str:
        """
        If enabled, select correct method of decryption and call encryption method.
        :param message: Incoming data for encryption
        :return: should return the encrypted data if enabled or decrypted data if disabled.
        """
        if self._enabled:
            if self._method == "caesar":
                return self.caesar_cipher_encrypt(message)
        return message

    def decrypt(self, message) -> str:
        """
        If enabled, select correct method of decryption and call decryption method.
        :param message: Incoming data for decryption
        :return: should return the decrypted data if enabled or encrypted data if disabled.
        """
        if self._enabled:
            if self._method == "caesar":
                return self.caesar_cipher_decrypt(message)
        return message

    def caesar_cipher_encrypt(self, message) -> str:
        """
        Encrypts incoming data and returns encrypted data.
        :param message: Takes plain-text input.
        :return: Should return encrypted data.
        """
        try:
            __encrypted = []
            for ch in message:
                __encrypted.append(chr(ord(ch) + self._caesar_key))
        except TypeError:
            return " "
        return ''.join(__encrypted)

    def caesar_cipher_decrypt(self, message) -> str:
        """
        Decrypts an incoming message and returns plain-text.
        :param message: Encrypted data.
        :return: Should return decrypted data as a single value.
        """
        try:
            __decrypted = []
            for ch in message:
                __decrypted.append(chr(ord(ch) - self._caesar_key))
        except TypeError:
            return ""
        return ''.join(__decrypted)

    def generate_common_mix(self):
        """
        Should  generate a pseudo-random value for a diffie-helman key exchange.
        """
        self._secret_key = randint(-8, 8)
        self._common_mix = self._secret_key + self._common_key

    def get_common_mix(self):
        return self._common_mix

    def generate_shared_secret(self, common_mix):
        self._shared_secret = int(common_mix) + self._secret_key
        self._caesar_key = self._shared_secret

    def create_log(self, sock, addr):
        if path.exists("Server\\Logs") == 1:
            _current_dt = get_date_time()
            _location_temp = ["Server\\Logs\\", _current_dt, ".txt"]
            self._log_location = ''.join(_location_temp)
            file = open(self._log_location, "w+")

            file.write(f"CONNECTION ESTABLISHED: {sock} | {addr}")
            file.close()
            return True
        else:
            return False

    def log(self, message):
        # Check file location
        if path.exists(self._log_location) == 1:
            count = 0
            all_file = []
            # Find previous line position
            with open(self._log_location, 'r') as file_read:
                for line in file_read:
                    all_file.append(line)
                    count += 1
                _previous = all_file[count - 1]
            # Generate hash of previous line and begin writing below that line.
            with open(self._log_location, 'a') as file_append:
                _previous_hash = NWSEncryption.hash_input(_previous)
                _date_time = get_date_time()
                _encrypted_date_time = data_caesar_cipher_encrypt(_date_time, self._base_key)
                _encrypted_message = data_caesar_cipher_encrypt(message, self._base_key)
                # You can easily switch between saving encrypted logs and plain-text by alternating the commented line.
                # Alternatively you can set the base key to 0 in the server_lib init for no base encryption of data or
                # logs though that is not necessarily recommended.
                # _write_to_file = f"{_date_time} | {self._user} | {message} | {_previous_hash}"
                _write_to_file = f"{_encrypted_date_time} | {self._user} | {_encrypted_message} | {_previous_hash}"

                file_append.write(f"\r{str(_write_to_file)}")
        else:
            return -1

    @staticmethod
    def hash_input(message):
        """
        Takes a string as input and hashes it using hashlib. Returns the output.
        :param message: Input to be hashed, type is irrelevant as long as it can be encoded.
        :return: Should return the MD5 hash of the parameter.
        """
        try:
            md5_hash = hashlib.md5()
            md5_hash.update(message.encode())
            return str(md5_hash.digest())
        except(NameError, ValueError, TypeError):
            print("error")
            return "hashing error, input lost"

    @staticmethod
    def hash_password(username):
        """
        Only admins are to have access to this.
        Checks for a username in a file then hashes that users password and salt together
        and appends it at the end of the file to allow for manual placing in file instead of password + salt
        :param username: username of user currently logged in.
        :return: return whether the hashing was a success or failure.
        """
        try:
            if path.exists("Server\\UandP.txt") == 1:
                with open("Server\\UandP.txt", "r+") as f:
                    for line in f:
                        line_found = line.split(" ")
                        if len(line) >= 3:
                            if line_found[0] in username:
                                __file_username = line_found[0]
                                __file_password = line_found[1]
                                __file_salt = line_found[2]
                                __file_combined = __file_password.join(__file_salt)
                                md5_hash = hashlib.md5()
                                md5_hash.update(__file_combined.encode())
                                __hashed_combined = md5_hash.digest()
                                f.write(f"{__file_username} {str(__hashed_combined)}")

                                return 1
                        else:
                            return -1
                    else:
                        return -1
            else:
                return -1
        except(NameError, ValueError, TypeError):
            print("Error in hashing, bad times for all.")  # TODO Stick a log here.
            return -1




