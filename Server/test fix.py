commands = {"login":  (str, self.login),
            "register": (str, self.register),
            "password": (str, self.password),
            "update": (list, self.update),
            "delete": (type(None), self.delete),
            "logout": (type(None), self.logout),
            "quit": (type(None), self.quit)}

base64characters = list("abcdefghijklmnopqrstuvwxyz"
                        "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
                        "01234567890+/")

def valid_credentials(username):
    """ returns true if the username or password is
    between 5 and 32 characters and is only alphanumeric"""
    return 5 <= len(username) <= 32 and all([x.isalnum() for x in username])


def validate_command(command, command_type=):
    if type(command) is tuple:
        instruction = command[0]
        try:
            argument = command[1]
        except IndexError:
            argument = None
        
        # Validate command
        if instruction == command_type and type(argument) is commands[command_type][0]:
            if command_type == "login":
                return True
            elif command_type == "password":
                return len(argument) == 43 and all([x in base64characters for x in argument])
            elif command_type == "register":
                return valid_credentials(argument)
            else:
                return True
        else:
            return False
    return False

class ClientConnection:

    def __init__(self, client)
        self.client = client
        self.username = ""
        self.setup()

    def setup(self):
        while True
            command = input("")
            if validate_command(command, "login"):
                self.login()
            elif validate_command(command, "register"):
                self.register()
            elif validate_command(command, "quit"):
                self.quit()
            else:
                print("Invalid command sent")
                client.close()
                break
            
