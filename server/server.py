import socket
from threading import Thread
from pickle import loads, dumps
import logindatabase
import databaseinterface
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
        connection, address = SERVER.accept()
        string = "{}:{} has connected.".format(*address)
        log_event(string)
        
        Thread(target=ClientConnection, args=(connection,)).start()
        addresses[connection] = address


def send_message(client, message):
    client.send(dumps(message))


def receive_message(client):
    try:
        msg = loads(client.recv(BUFFER_SIZE))
        if msg is not None:
            log_event("{}:{} sent: {}".format(*addresses[client], msg))
            return msg
    except OSError:  # Possibly client has left the chat.
        pass


def current_time():
    time = str(datetime.now().time())
    return time[:time.find(".")]


def log_event(string):
    string = "{} {}".format(current_time(), string)
    print(string)
    event_log.append(string)


def server_log():
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
    between 5 and 32 characters and is only alphanumeric"""
    return 5 <= len(username) <= 32 and all([x.isalnum() for x in username])


def validate_command(command, command_type):
    """Returns true if is a valid command, and of the type expected"""
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
    """Handles an instance of a client"""

    def __init__(self, client):
        self.client = client
        self.username = ""
        self.awaiting_login = True

        self.setup()

    def setup(self):
        self.username = ""
        self.awaiting_login = True
        
        while self.awaiting_login:
            command = receive_message(self.client)
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
            send_message(self.client, ("salt", logindatabase.get_salt(username)))
            password = receive_message(self.client)[1]
            if logindatabase.verify_hash(username, password):
                self.username = username
                self.awaiting_login = False
                send_message(self.client, ("login_granted",))
            else:
                send_message(self.client, ("login_denied",))
            del password
        else:
            send_message(self.client, ("login_denied",))

    def register(self, username):
        if not logindatabase.username_exists(username):
            salt = logindatabase.generate_salt()
            send_message(self.client, ("salt", salt))
            password = receive_message(self.client)[1]

            self.username = username
            self.awaiting_login = False
            # create account
            logindatabase.add(self.username, password, salt)
            del password, salt
        else:
            send_message(self.client, ("username_taken",))

    def quit(self):
        self.client.close()
        self.awaiting_login = False
        log_event("{}:{} has disconnected".format(*addresses[self.client]))

    def run(self):
        access = True
        runsetup = False
        user = databaseinterface.DatabaseInterface(self.username)
        send_message(self.client, ("accounts", user.get_accounts()))

        while access:
            command = receive_message(self.client)
            if validate_command(command, "delete_user"):
                user.delete_user()
                logindatabase.delete_user(self.username)
                del addresses[self.client]

            elif validate_command(command, "logout"):
                access = False
                runsetup = True

            elif validate_command(command, "update"):
                user.update_table(command[1])

            elif validate_command(command, "quit"):
                self.client.close()
                access = False
                del addresses[self.client]

            elif command is not None:
                log_event("Invalid command sent: {}".format(command))
                self.client.close()
                access = False
                del addresses[self.client]

        if runsetup:
            self.setup()


HOST = socket.gethostbyname(socket.gethostname())
PORT = 33000
BUFFER_SIZE = 2048
TOTAL_CLIENTS = 8

SERVER = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
SERVER.bind((HOST, PORT))

addresses = {}
event_log = []

if __name__ == "__main__":
    SERVER.listen(TOTAL_CLIENTS)
    Thread(target=server_log).start()
    accept_incoming_connections()
    SERVER.close()
