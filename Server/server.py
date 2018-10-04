import socket
from threading import Thread
from pickle import loads, dumps, UnpicklingError
import lib.logindb as logindb
import lib.datadb as datadb
import lib.diffiehellman as diffiehellman
import lib.serverconfig as serverconfig
from time import sleep
from datetime import datetime
import os
from hashlib import sha256


# All commands

# During login - inbound
# ("login", "username")
# ("register", "username")
# ("password", "salted password hash")

# During login - outbound
# ("login_granted", )
# ("login_denied", )
# ("username_taken", )
# ("salt", salt)

# Once logged in - outbound
# ("accounts", accounts)

# Once logged in - inbound
# ("update", tableinfo)
# ("delete", )
# ("logout", )
# ("quit", )

commands = {"login":  str,
            "register": str,
            "password": str,
            "update": list,
            "delete_user": type(None),
            "logout": type(None),
            "quit": type(None)}


def is_hex(string):
    """Returns true if string is valid hexidecimal"""
    try:
        int(string, 16)
        return True
    except ValueError:
        return False


def accept_incoming_connections():
    """ accepts connection from incoming clients """

    log_event("Hosting server at {} on port {}".format(HOST, PORT))
    print("Waiting for connection...")
    
    while True:
        connection, address = server.accept()
        log_event("{}:{} has connected.".format(*address))
        if not whitelist_enabled or address[0] in whitelist_ips:
            response = connection.recv(BUFFER_SIZE).decode()
            if response == "OK":
                connection.send(bytes("OK", "utf8"))
                Thread(target=ClientConnection, args=(connection, address)).start()
        else:
            connection.send(bytes("NO", "utf8"))
            log_event("{}:{} was forcefully disconnected as it was not on the whitelist".format(*address))
            connection.close()


def current_time():
    """ returns current time in HH:MM:SS """
    time = str(datetime.now().time())
    return time[:time.find(".")]


def log_event(string):
    """ prints string and adds string to event log with current time """
    string = "{} {}".format(current_time(), string)
    print(string)
    event_log.append(string)


def server_log():
    """ log events and record in .txt in /serverlogs """
    if not os.path.exists(serverlog_directory):
        os.makedirs(serverlog_directory)

    global event_log

    while True:
        sleep(30)  # wait 30 seconds
        if event_log:
            path = "{}/{}.txt".format(serverlog_directory, datetime.now().strftime("%Y-%m-%d"))
            with open(path, mode="a", encoding="utf8") as logfile:
                for line in event_log:
                    logfile.write(line+"\n")
            event_log = []


def valid_credentials(credential):
    """ returns true if the username or password is
    between 5 and 32 characters and is only alphanumeric """
    return 5 <= len(credential) <= 32 and all([x.isalnum() for x in credential])


def validate_command(command, command_type):
    """ returns true if is a valid command, and of the type expected """
    if type(command) is tuple:
        instruction = command[0]
        try:
            argument = command[1]
        except IndexError:
            argument = None
        
        # Validate command
        if instruction == command_type and type(argument) is commands[command_type]:
            if command_type == "login":
                return True
            elif command_type == "password":
                # has to be a default sha256 hash
                return len(argument) == 64 and all(is_hex(char) for char in argument)
            elif command_type == "register":
                return valid_credentials(argument)
            else:
                return True
        else:
            return False
    return False


class ClientConnection:
    """ manages communication to a client """

    def __init__(self, client, address):
        self.client = client
        self.address = address

        # Create a shared key through diffie-hellman key exchange
        d = diffiehellman.DiffieHellman()
        client_key = int(self.client.recv(BUFFER_SIZE).decode())
        self.client.send(bytes(str(d.get_public_key()), "utf8"))
        self.seed = str(d.get_shared_key(client_key))
        # print("Established key: ", self.seed)

        self.key = ""
        
        self.username = ""
        self.awaiting_login = True
        self.access = False

        self.setup()

    def encrypt(self, message):
        self.key = int(sha256(self.seed.encode()).hexdigest(), 16)
        self.seed = str(self.key)
        self.key = bin(self.key)[2:]

        # Concatenate all bytes in message to create binary string
        message_binary = ""
        for byte in message:
            message_binary = "{:0>8}".format(bin(byte)[2:]) + message_binary

        while len(self.key) < len(message_binary):
            seed_hash = int(sha256(self.seed.encode()).hexdigest(), 16)
            self.seed = str(seed_hash)
            self.key += bin(seed_hash)[2:]

        self.key = self.key[:len(message_binary)]

        vernam = bin(int(self.key, 2) ^ int(message_binary, 2))[2:]
        if len(vernam) % 8 != 0:
            vernam = (8-(len(vernam) % 8)) * '0' + vernam

        # Get bytes out of message
        bytelist = []
        for i in range(0, len(vernam), 8):
            byte = int(vernam[i: i+8], 2)
            bytelist = [byte] + bytelist

        return bytes(bytelist)

    def send_message(self, message):
        """ send a messsage to client"""
        message = self.encrypt(dumps(message))
        self.client.send(message)

    def receive_message(self):
        """ receive one message from the client """
        try:
            message = self.encrypt(self.client.recv(BUFFER_SIZE))
            message = loads(message)

            if message is not None:
                log_event("{}:{} sent: {}".format(*self.address, message))
                return message
        except UnpicklingError:
            print("Unpickling error: invalid encryption/ decryption? :{}")
        except OSError:
            pass

    def setup(self):
        """ manages the users command until logged in or disconnected """
        self.username = ""
        self.awaiting_login = True
        
        while self.awaiting_login:
            command = self.receive_message()
            if validate_command(command, "login"):
                self.login(command[1])
            elif validate_command(command, "register"):
                self.register(command[1])
            elif validate_command(command, "quit"):
                self.quit()
            else:
                log_event("Invalid command sent: {}".format(str(command)))
                self.client.close()
                self.awaiting_login = False

        if self.username:
            self.run()

    def login(self, username):
        """ handles the commands sent for the login procedure """
        if logindb.username_exists(username):
            self.send_message(("salt", logindb.get_salt(username)))
            password = self.receive_message()[1]
            if logindb.verify_hash(username, password):
                self.username = username
                log_event("{}:{} has logged in to the account '{}'".format(*self.address, self.username))
                self.awaiting_login = False
                self.send_message(("login_granted",))
            else:
                self.send_message(("login_denied",))
        else:
            self.send_message(("login_denied",))

    def register(self, username):
        """ handles the commands sent for the register procedure """
        if not logindb.username_exists(username):
            salt = logindb.generate_salt()
            self.send_message(("salt", salt))
            password = self.receive_message()[1]

            self.username = username
            self.awaiting_login = False
            # create account
            logindb.add(self.username, password, salt)
            log_event("{}:{} has registered the account '{}'".format(*self.address, self.username))
        else:
            self.send_message(("username_taken",))

    def quit(self):
        """ handles the client quiting """
        self.client.close()
        self.awaiting_login = False
        self.access = False
        log_event("{}:{} has disconnected".format(*self.address))

    def run(self):
        """ handles the client quiting """
        self.access = True
        run_setup = False
        user = datadb.DatabaseInterface(self.username)
        self.send_message(("accounts", user.get_accounts()))

        while self.access:
            command = self.receive_message()
            if validate_command(command, "delete_user"):
                user.delete_user()
                logindb.delete_user(self.username)
                self.quit()

            elif validate_command(command, "logout"):
                self.access = False
                run_setup = True

            elif validate_command(command, "update"):
                user.update_table(command[1])

            elif validate_command(command, "quit"):
                self.quit()

            elif command is not None:
                log_event("Invalid command sent: {}".format(command))
                self.quit()

        if run_setup:
            self.setup()


event_log = []

# Collect variable values from configfile
HOST = socket.gethostbyname(socket.gethostname())
PORT = serverconfig.connection["port"]
CLIENT_MAX = serverconfig.connection["client max"]
whitelist_enabled = serverconfig.connection["whitelist"]
BUFFER_SIZE = serverconfig.connection["buffer size"]

serverlog_enabled = serverconfig.files["serverlog"]
serverlog_directory = serverconfig.files["serverlog directory"]
userdata_name = serverconfig.files["userdata db dir"]
registered_accounts_name = serverconfig.files["registered accounts db dir"]

datadb.initialize(userdata_name)
logindb.initialize(registered_accounts_name)

server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
server.bind((HOST, PORT))

if whitelist_enabled:
    with open("whitelist.txt", mode="r", encoding="utf8") as file:
        temp = file.read().replace(" ", "").split("\n")
        whitelist_ips = []
        # Remove empty entries from blank lines
        for i in temp:
            if i:
                whitelist_ips.append(i)

if __name__ == "__main__":
    server.listen(CLIENT_MAX)
    if serverlog_enabled:
        Thread(target=server_log).start()
    accept_incoming_connections()
    server.close()
    datadb.close()
    logindb.close()
