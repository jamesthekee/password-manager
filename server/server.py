import socket
from threading import Thread
from pickle import loads, dumps
import logindatabase
import databaseinterface
import diffiehellman
from time import sleep
from datetime import datetime
import os

# The protocol for communication is sending a tuple 
# They are formatted as so: ("instruction", "argument")
# They are sent using the loads and dumps method of pickle


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
    log_event("Hosting server at {}".format(HOST))
    print("Waiting for connection...")
    
    while True:
        connection, address = server.accept()
        log_event("{}:{} has connected.".format(*address))
        
        Thread(target=ClientConnection, args=(connection, address)).start()


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

    if not os.path.exists("serverlogs"):
        os.makedirs("serverlogs")

    event_log = []
    while True:
        sleep(30)  # wait 30 seconds
        if event_log:
            path = "serverlogs/{}.txt".format(datetime.now().strftime("%Y-%m-%d"))
            with open(path, mode="a", encoding="utf8") as file:
                for line in event_log:
                    file.write(line+"\n")
            event_log = []


def valid_credentials(username):
    """ returns true if the username or password is
    between 5 and 32 characters and is only alphanumeric """
    return 5 <= len(username) <= 32 and all([x.isalnum() for x in username])


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
    """ handles an communication between server and a client """

    def __init__(self, client, address):
        self.client = client
        self.address = address

        # Create a shared key through diffie-hellman key exchange
        d = diffiehellman.DiffieHellman()
        client_key = int(self.client.recv(BUFFER_SIZE).decode())
        self.client.send(bytes(str(d.get_public_key()), "utf8"))
        self.key = d.get_shared_key(client_key)
        
        self.username = ""
        self.awaiting_login = True
        self.access = False

        self.setup()

    def send_message(self, message):
        self.client.send(dumps(message))

    def receive_message(self):
        try:
            msg = loads(self.client.recv(BUFFER_SIZE))
            if msg is not None:
                log_event("{}:{} sent: {}".format(*self.address, msg))
                return msg
        except OSError:
            pass

    def setup(self):
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
        if logindatabase.username_exists(username):
            self.send_message(("salt", logindatabase.get_salt(username)))
            password = self.receive_message()[1]
            if logindatabase.verify_hash(username, password):
                self.username = username
                self.awaiting_login = False
                self.send_message(("login_granted",))
            else:
                self.send_message(("login_denied",))
        else:
            self.send_message(("login_denied",))

    def register(self, username):
        if not logindatabase.username_exists(username):
            salt = logindatabase.generate_salt()
            self.send_message(("salt", salt))
            password = self.receive_message()[1]

            self.username = username
            self.awaiting_login = False
            # create account
            logindatabase.add(self.username, password, salt)
        else:
            self.send_message(("username_taken",))

    def quit(self):
        self.client.close()
        self.awaiting_login = False
        self.access = False
        log_event("{}:{} has disconnected".format(*self.address))

    def run(self):
        self.access = True
        run_setup = False
        user = databaseinterface.DatabaseInterface(self.username)
        self.send_message(("accounts", user.get_accounts()))

        while self.access:
            command = self.receive_message()
            if validate_command(command, "delete_user"):
                user.delete_user()
                logindatabase.delete_user(self.username)
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


HOST = socket.gethostbyname(socket.gethostname())
PORT = 33000
BUFFER_SIZE = 2048
TOTAL_CLIENTS = 8

event_log = []

server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
server.bind((HOST, PORT))

if __name__ == "__main__":
    server.listen(TOTAL_CLIENTS)
    Thread(target=server_log).start()
    accept_incoming_connections()
    server.close()
