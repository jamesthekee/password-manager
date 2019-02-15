import socket
from threading import Thread
from pickle import loads, dumps, UnpicklingError
import time
from datetime import datetime
from hashlib import sha256
import os
import lib.logindb as logindb
import lib.datadb as datadb
import lib.diffiehellman as diffiehellman
import lib.serverconfig as serverconfig
import lib.encrypt as encryption


event_log = []

# Collect variable values from configfile
HOST = socket.gethostbyname(socket.gethostname())
PORT = serverconfig.connection["port"]
CLIENT_MAX = serverconfig.connection["client max"]
whitelist_enabled = serverconfig.connection["whitelist"]
BUFFER_SIZE = serverconfig.connection["buffer size"]

serverlog_enabled = serverconfig.files["serverlog"]
serverlog_directory = serverconfig.files["serverlog directory"]
whitelist_directory = serverconfig.files["whitelist directory"]
userdata_name = serverconfig.files["userdata db dir"]
registered_accounts_name = serverconfig.files["registered accounts db dir"]

# Initialize databases
datadb.initialize(userdata_name)
logindb.initialize(registered_accounts_name)

server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
server.bind((HOST, PORT))

# Extract whitelisted names from files
if whitelist_enabled:
    with open(whitelist_directory, mode="r", encoding="utf8") as file:
        temp = file.read().replace(" ", "").split("\n")
        whitelist_ips = []
        # Remove empty entries from blank lines
        for i in temp:
            if i:
                whitelist_ips.append(i)


# All commands

# During login - inbound
# ("login", "username")
# ("register", "username")
# ("password", "salted password hash")

# During login - outbound
# ("login_granted",)
# ("login_denied",)
# ("username_taken",)
# ("salt", salt)

# Once logged in - outbound
# ("accounts", accounts)

# Once logged in - inbound
# ("update", tableinfo)
# ("delete",)
# ("logout",)
# ("quit",)


# Dictionary for expected datatypes of commands
commands = {"login": tuple,
            "register": tuple,
            "update": list,
            "delete_user": type(None),
            "logout": type(None),
            "quit": type(None)}


def is_hex(string):
    """ Returns true if string is valid hexidecimal. """
    try:
        int(string, 16)
        return True
    except ValueError:
        return False


def accept_incoming_connections():
    """ Accepts connection from incoming clients. """

    log_event("Hosting server at {} on port {}".format(HOST, PORT))
    print("Waiting for connection...")
    
    while True:
        connection, address = server.accept()
        log_event("{}:{} has connected.".format(address[0], address[1]))
        if not whitelist_enabled or address[0] in whitelist_ips:
            response = connection.recv(BUFFER_SIZE).decode()
            if response == "OK":
                connection.send(bytes("OK", "utf8"))
                Thread(target=ClientConnection, args=(connection, address)).start()
        else:
            connection.send(bytes("NO", "utf8"))
            log_event("{}:{} was forcefully disconnected as it was not on the whitelist".format(address[0], address[1]))
            connection.close()


def current_time():
    """ Returns current time in HH:MM:SS format. """

    return datetime.now().strftime("%H:%M:%S")


def log_event(string):
    """ Prints string and appends the string to the event log with current time. """

    string = "{} {}".format(current_time(), string)
    print(string)
    if serverlog_enabled:
        event_log.append(string)


def server_log():
    """ Records logged events in a txt file. """

    if not os.path.exists(serverlog_directory):
        os.makedirs(serverlog_directory)

    global event_log

    while True:
        time.sleep(30)
        # If there are events to log
        if event_log:
            path = "{}/{}.txt".format(serverlog_directory, datetime.now().strftime("%Y-%m-%d"))
            with open(path, mode="a", encoding="utf8") as logfile:
                for line in event_log:
                    logfile.write(line+"\n")
            event_log = []


def validate_credentials(credential):
    """ Returns true if the username or password is
    between 5 and 32 characters and is only alphanumeric. """

    return 5 <= len(credential) <= 32 and credential.isalnum()

 
def validate_command(command, command_type):
    """ Returns true if is a valid command of the expected type, with the appropriate argument. """

    if type(command) is tuple:
        instruction = command[0]
        try:
            argument = command[1]
        except IndexError:
            argument = None
        
        # Validate command
        if instruction == command_type and type(argument) is commands[command_type]:
            if command_type == "register" or command_type == "login":
                if len(argument) == 2 and len(argument[1]) == 64 and \
                 all(is_hex(char) for char in argument[1]):
                    if command_type == "register":
                        username = argument[0]
                        return validate_credentials(username)
                    return True
            return True
    return False


class ClientConnection:
    """ Manages the communication to a client. """

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
        """ Perform vernam cipher on message using key generated from seed. """

        encrypted, new_seed = encryption.encrypt(message, self.seed)
        self.seed = new_seed
        return encrypted

    def send_message(self, message):
        """ Sends a messsage to a client. """

        message = self.encrypt(dumps(message))
        self.client.send(message)

    def receive_message(self):
        """ Receive one message from the client. """

        try:
            message = self.encrypt(self.client.recv(BUFFER_SIZE))
            message = loads(message)

            if message is not None:
                log_event("{}:{} sent: {}".format(self.address[0], self.address[0], message))
                return message
        except UnpicklingError:
            print("Unpickling error: invalid encryption/ decryption? :{}")
        except OSError:
            pass

    def setup(self):
        """ Manages the users commands until logged in or disconnected. """

        self.username = ""
        self.awaiting_login = True
        
        while self.awaiting_login:
            command = self.receive_message()
            if validate_command(command, "login"):
                self.login(command[1][0], command[1][1])
            elif validate_command(command, "register"):
                self.register(command[1][0], command[1][1])
            elif validate_command(command, "quit"):
                self.quit()
            else:
                log_event("Invalid command sent: {}".format(str(command)))
                self.client.close()
                self.awaiting_login = False

        if self.username:
            self.run()

    def login(self, username, password):
        """ Handles a login command. """

        print("Login {} {}".format(username, password))

        if logindb.username_exists(username):
            password_hash = sha256((password + logindb.get_salt(username)).encode()).hexdigest()
            if logindb.verify_hash(username, password_hash):
                self.username = username
                log_event("{}:{} has logged in to the account '{}'".format(self.address[0], self.address[1], self.username))
                self.awaiting_login = False
                self.send_message(("login_granted",))
            else:
                self.send_message(("login_denied",))
        else:
            self.send_message(("login_denied",))

    def register(self, username, password):
        """ Handles a register command. """

        print("Register {} {}".format(username, password))

        if not logindb.username_exists(username):
            salt = logindb.generate_salt()
            self.username = username
            password_hash = sha256((password + salt).encode()).hexdigest()
            self.awaiting_login = False
            # create account
            logindb.add(self.username, password_hash, salt)
            log_event("{}:{} has registered the account '{}'".format(self.address[0], self.address[1], self.username))
        else:
            self.send_message(("username_taken",))

    def quit(self):
        """ Handles the client quiting. """

        self.client.close()
        self.awaiting_login = False
        self.access = False
        log_event("{}:{} has disconnected".format(self.address[0], self.address[1]))

    def run(self):
        """ Handles an instance of a logged in client. """

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


if __name__ == "__main__":
    server.listen(CLIENT_MAX)
    if serverlog_enabled:
        Thread(target=server_log).start()
    accept_incoming_connections()
    server.close()
    datadb.close()
    logindb.close()
