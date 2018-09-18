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
            "delete": type(None),
            "logout": type(None),
            "quit": type(None)}

base64characters = list("abcdefghijklmnopqrstuvwxyz"
                        "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
                        "01234567890+/")

def accept_incoming_connections():
    """ accepts connection from incoming clients """

    print("Hosting server at {}".format(HOST))
    print("Waiting for connection...")
    
    while True:
        connection, address = SERVER.accept()
        event = "{}  {}:{} has connected.".format(current_time(), *address)
        
        print(event)
        eventlog.append(event)
        
        Thread(target=handle_client, args=(connection,)).start()
        addresses[connection] = address


def send_message(client, message):
    client.send(dumps(message))


def receive_message(client):
    while True:
        try:
            msg = loads(client.recv(BUFFER_SIZE))
            if msg is not None:
                event = "{}  {}:{} sent: {}".format(current_time(), addresses[client][0], addresses[client][1], msg)
                print(event)
                eventlog.append(event)
                return msg
        except OSError:  # Possibly client has left the chat.
            break


def current_time():
    time = str(datetime.now().time())
    return time[:time.find(".")]


def server_log():
    if not os.path.exists("serverlogs"):
        os.makedirs("serverlogs")
    while True:
        sleep(30)  # wait 30 seconds
        if eventlog:
            path = "serverlogs/{}.txt".format(datetime.now().strftime("%Y-%m-%d"))
            with open(path, mode="a", encoding="utf8") as file:
                for line in eventlog:
                    file.write(line+"\n")
            eventlog = []


def valid_credentials(username):
    """ returns true if the username or password is
    between 5 and 32 characters and is only alphanumeric"""
    return 5 <= len(username) <= 32 and all([x.isalnum() for x in username])


def validate_command(command, command_type):
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
                return len(argument) == 43 and all([x in base64characters for x in argument])
            elif command_type == "register":
                return valid_credentials(argument)
        else:
            return False
    return False


def handle_client(client):
    """ handles a single client connection until it disconnects """

    # LOGIN
    # 1. Client sends login request with name
    # 2. if valid name, server sends associated salt
    # 3. client returns the salted hash of its password
    # 4. if its valid then login granted sent
    # 5. associate database sent

    # REGISTER
    # 1. Client sends register request with name
    # 2. If valid salt is created and sent to client
    # 3. Client sends salted hash
    # 4. username, salted hash and salt stored in login database
    # 5. empty database sent
    
    # spaghetti code to run through login or register procedure
    username = ""
    while username == "":
        command = receive_message(client)
        if validate_command(command, "login"):
            if logindatabase.username_exists(command[1]):
                send_message(client, ("salt", logindatabase.get_salt(command[1])))
                password = receive_message(client)[1]
                if logindatabase.verify_hash(command[1], password):
                    username = command[1]
                    send_message(client, ("login_granted", ))
                else:
                    send_message(client, ("login_denied",))
                del password
            else:
                send_message(client, ("login_denied",))

        elif validate_command(command, "register"):
            if not logindatabase.username_exists(command[1]):
                salt = logindatabase.generate_salt()
                send_message(client, ("salt", salt))
                password = receive_message(client)[1]
                username = command[1]

                # create account
                logindatabase.add(username, password, salt)
                del password, salt
            else:
                send_message(client, ("username_taken",))
        elif command == ("quit", ):
            client.close()
            break
        
    # If login successful
    if username:
        access = True
        user = databaseinterface.DatabaseInterface(username)
        send_message(client, ("accounts", user.get_accounts()))
        while access:
            command = receive_message(client)
            if command != ("quit", ):
                if command == ("delete_user", ):
                    user.delete_user()
                    logindatabase.delete_user(username)
                    del addresses[client]
                elif command == ("logout", ):
                    access = False
                    handle_client(client)
                    del addresses[client]
                elif command[0] == "update":
                    user.update_table(command[1])
            else:
                client.close()
                access = False
                del addresses[client]


HOST = socket.gethostbyname(socket.gethostname())
PORT = 33000
BUFFER_SIZE = 2048
TOTAL_CLIENTS = 8

SERVER = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
SERVER.bind((HOST, PORT))

addresses = {}
eventlog = []

if __name__ == "__main__":
    SERVER.listen(TOTAL_CLIENTS)
    Thread(target=server_log).start()
    accept_incoming_connections()
    SERVER.close()
