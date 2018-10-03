import tkinter as tk
import tkinter.ttk as ttk
import tkinter.messagebox
from socket import AF_INET, socket, SOCK_STREAM
from pickle import loads, dumps, UnpicklingError
from hashlib import sha256
from codecs import encode, decode
from time import sleep
from threading import Thread
import diffiehellman
import clientconfig


class ServerConnection:
    """ manages communication with server """

    def __init__(self):
        self.socket = None
        self.connected = False
        self.connect()

        if self.connected:
            # establish shared diffie-hellman key exchange

            d = diffiehellman.DiffieHellman()
            self.socket.send(bytes(str(d.get_public_key()), "utf8"))
            server_key = int(self.socket.recv(BUFFER_SIZE).decode())
            self.seed = str(d.get_shared_key(server_key))
            # print("Established key: ", self.seed)

            self.key = ""

            app = Application(self)
            app.mainloop()
        else:
            quit()

    def encrypt(self, message):
        """ perform vernam cipher on message using key generated from seed"""
        self.key = int(sha256(self.seed.encode()).hexdigest(), 16)
        self.seed = str(self.key)
        self.key = bin(self.key)[2:]

        # Concatenate all bytes in message to create binary string
        message_binary = ""
        for byte in message:
            message_binary = "{:0>8}".format(bin(byte)[2:]) + message_binary

        # Ensure key length is sufficient
        while len(self.key) < len(message_binary):
            seed_hash = int(sha256(self.seed.encode()).hexdigest(), 16)
            self.seed = str(seed_hash)
            self.key += bin(seed_hash)[2:]

        # Trim key to exact length of message
        self.key = self.key[:len(message_binary)]

        # perform xor on key and message
        vernam = bin(int(self.key, 2) ^ int(message_binary, 2))[2:]
        if len(vernam) % 8 != 0:
            vernam = (8-(len(vernam) % 8)) * '0' + vernam

        # convert vernam cipher into bytes object
        bytelist = []
        for i in range(0, len(vernam), 8):
            byte = int(vernam[i: i+8], 2)
            bytelist = [byte] + bytelist

        return bytes(bytelist)

    def connect(self):
        """ attempt to connect to host"""
        connecting = True

        while connecting:
            try:
                self.socket = socket(AF_INET, SOCK_STREAM)
                self.socket.connect((HOST, PORT))
                connecting = False
                self.connected = True
            except (TimeoutError, ConnectionRefusedError):
                connecting = tk.messagebox.askretrycancel(
                    "Disconnected", "Unable to connect to server, would you like to retry?")

    def send_message(self, message):
        """ Send a message to server"""
        message = self.encrypt(dumps(message))
        self.socket.send(message)

    def receive_message(self):
        """ Wait for a reply from server and return"""
        try:
            message = loads(self.encrypt(self.socket.recv(BUFFER_SIZE)))
            if message is not None:
                print("Server sent: {}".format(message))
                return message
        except UnpicklingError:
            print("Unpickling error: invalid encryption/ decryption? ")
        except OSError:
            print("Disconnected ?")

    def close(self):
        """ close connection """
        self.socket.close()


def valid_credentials(credential):
    """ returns true if the username or password is
    between 5 and 32 characters and is only alphanumeric"""
    return 5 <= len(credential) <= 32 and all([x.isalnum() for x in credential])


class Application(tk.Tk):
    """ Tkinter window that can change between frame"""

    def __init__(self, server_connection):
        tk.Tk.__init__(self)
        self.resizable(False, False)
        self.title("KeeSecurity")
        self.iconbitmap("keesecurity.ico")
        self.server = server_connection

        self.frame_ = None
        self.switch_frame(LoginPage)

    def switch_frame(self, frame_class, *args):
        """Destroys current frame and replaces it with a new one"""
        if self.frame_ is not None:
            self.frame_.destroy()
        self.frame_ = frame_class(self, *args)
        self.frame_.pack(anchor="w")


class LoginPage(tk.Frame):
    """tk Frame that displays the login window"""

    def __init__(self, master):
        tk.Frame.__init__(self, master)
        self.master = master

        master.geometry("320x240")
        master.protocol("WM_DELETE_WINDOW", self.on_closing)

        # Create Labels
        username_label = tk.Label(self, text="Username")
        password_label = tk.Label(self, text="Password")

        username_label.grid(row=1, column=0, sticky='e', padx=(50, 0), pady=(50, 2))
        password_label.grid(row=2, column=0, sticky='e', padx=(50, 0), pady=(2, 2))

        # Create entries
        self.username_entry = tk.Entry(self)
        self.password_entry = tk.Entry(self, show="*")

        self.username_entry.grid(row=1, column=1, columnspan=2, pady=(50, 2))
        self.password_entry.grid(row=2, column=1, columnspan=2, pady=(2, 2))

        # Create buttons
        self.login_button = tk.Button(self, text="Login", command=self.login)
        self.register_button = tk.Button(self, text="Register", command=self.register)

        self.login_button.grid(row=3, column=1, sticky='ew')
        self.register_button.grid(row=3, column=2, sticky='ew')

        # Message label
        self.message_label = tk.Label(self, text="", foreground="red")
        self.message_label.grid(row=4, column=0, columnspan=3, sticky='e')

    def login(self):
        username = self.username_entry.get()
        password = self.password_entry.get()
        self.username_entry.delete(0, "end")
        self.password_entry.delete(0, "end")

        self.login_procedure(username, password)

    def register(self):
        username = self.username_entry.get()
        password = self.password_entry.get()
        if valid_credentials(username) and valid_credentials(password):
            self.register_procedure(username, password)
        else:
            self.message_label.config(text="Invalid username or password")

    def login_procedure(self, username, password):
        self.master.server.send_message(("login", username))
        msg = self.master.server.receive_message()
        if msg[0] == "salt":
            salt = msg[1]
            password_hash = sha256((password + salt).encode()).hexdigest()
            self.master.server.send_message(("password", password_hash))
            msg = self.master.server.receive_message()
            if msg == ("login_granted",):
                accounts = self.master.server.receive_message()[1]
                self.master.switch_frame(DatabaseViewer, accounts, password)
            elif msg == ("login_denied",):
                self.message_label.config(text="Invalid login details")
        elif msg == ("login_denied",):
            self.message_label.config(text="Invalid login details")

    def register_procedure(self, username, password):
        """ send commands for register procedure """
        self.master.server.send_message(("register", username))
        msg = self.master.server.receive_message()
        if msg != ("username_taken",):
            salt = msg[1]
            password_hash = sha256((password + salt).encode()).hexdigest()
            self.master.server.send_message(("password", password_hash))
            accounts = self.master.server.receive_message()[1]
            self.master.switch_frame(DatabaseViewer, accounts, password)
        else:
            self.message_label.config(text="Username taken")

    def on_closing(self):
        """ close application """
        try:
            self.master.server.send_message(("quit",))
        except OSError:  # Not connected
            pass
        self.master.server.close()
        self.master.destroy()


class DatabaseViewer(tk.Frame):
    """tk Frame that displays the database viewer window"""

    def __init__(self, master, accounts, password):
        tk.Frame.__init__(self, master)

        self.master = master
        self.password = password
        self.popup = False

        master.geometry("760x460")
        master.protocol("WM_DELETE_WINDOW", self.on_closing)

        # if not empty
        # convert each tuple inside the list into a list
        if accounts:
            self.accounts = [list(x) for x in accounts]
        else:
            self.accounts = accounts

        # GUI SETUP

        # create menu
        menu = tk.Menu(master)
        master.config(menu=menu)

        product_information = """This password manager is an A-Level project written by James Kee 
        More information is available at https://github.com/jamesthekee/password-manager"""

        submenu = tk.Menu(menu)
        menu.add_cascade(label="More", menu=submenu)
        submenu.add_command(label="Logout", command=self.logout)
        submenu.add_command(label="Information",
                            command=lambda: tkinter.messagebox.showinfo("Product Information",
                                                                        product_information))
        submenu.add_separator()
        submenu.add_command(label="Delete Account", command=self.delete_account)

        # Create table(Tree view)

        # associated variables
        self.row_selected = 0
        self.column_selected = 0
        self.start_index = 0

        self.table = ttk.Treeview(self, height=20,
                                  columns=("service", "login", "password", "notes"), selectmode="browse")

        self.table.heading('#0', text='', anchor=tk.CENTER)
        self.table.heading('#1', text='service', anchor=tk.CENTER)
        self.table.heading('#2', text='login', anchor=tk.CENTER)
        self.table.heading('#3', text='password', anchor=tk.CENTER)
        self.table.heading('#4', text='notes', anchor=tk.CENTER)

        self.table.column('#0', stretch=True, minwidth=40, width=40)   # row number
        self.table.column('#1', stretch=True, minwidth=50, width=100)  # service
        self.table.column('#2', stretch=True, minwidth=50, width=100)  # login
        self.table.column('#3', stretch=True, minwidth=50, width=60)   # password
        self.table.column('#4', stretch=True, minwidth=50, width=200)  # notes

        self.table.grid(row=0, column=0, rowspan=16, columnspan=3, sticky="we", padx=(0, 0), pady=(2, 0))
        self.update_table()

        self.table.bind('<Button-1>', self.table_click)

        self.scrollbar = ttk.Scrollbar(self, orient="vertical", command=self.table.yview)
        self.scrollbar.grid(row=0, column=3, rowspan=16, columnspan=1, sticky="nsw", padx=(0, 0), pady=(0, 0))
        self.table.configure(yscrollcommand=self.scrollbar.set)

        # TOOL BUTTONS

        self.edit_label = tk.Label(self, text="Edit textbox")
        self.edit_textbox = tk.Text(self, height=4, width=24, state="disabled")
        self.edit_button = tk.Button(self, text="apply edit", command=self.edit_entry, state="disabled")

        self.edit_label.grid(row=0, column=4, rowspan=1, columnspan=3, sticky="sw", padx=(10, 0), pady=(2, 2))
        self.edit_textbox.grid(row=1, column=4, rowspan=6, columnspan=3, sticky="nse", padx=(10, 0), pady=(2, 0))
        self.edit_button.grid(row=7, column=6, sticky="new", pady=(5, 0))

        self.copy_password_button = tk.Button(self, text="Copy password", command=self.copy_password, state="disabled")
        self.copy_login_button = tk.Button(self, text="Copy login", command=self.copy_login, state="disabled")
        self.add_button = tk.Button(self, text="add", command=self.add_entry)
        self.delete_button = tk.Button(self, text="delete", command=self.delete_entry, state="disabled")

        self.copy_login_button.grid(row=10, column=4, sticky="ew", padx=(10, 0), pady=(5, 0))
        self.add_button.grid(row=15, column=4, sticky="sew", padx=(10, 0))
        self.copy_password_button.grid(row=10, column=6, sticky="ew", padx=(0, 0), pady=(5, 0))
        self.delete_button.grid(row=15, column=6, sticky="sew", padx=(0, 2))

    def table_click(self, event):
        """ Triggers when table clicked"""
        region = self.table.identify_region(event.x, event.y)
        if region == "separator":
            return "break"
        elif region == "heading":
            pass
        else:  # region == "cell"
            self.cell_selection(event)

    def cell_selection(self, event):
        """ Function to retrieve row and column number selected"""

        # Get cell coordinates
        row = self.table.identify_row(event.y)
        col = self.table.identify_column(event.x)

        if row != "":  # CELL SELECTED

            self.row_selected = int(row[1:], 16) - 1
            self.column_selected = int(col[1:])
            # row format is #I00A8 or ""
            # col format is #4

            # Enable selection dependant buttons
            self.delete_button.config(state="normal")
            self.copy_password_button.config(state="normal")
            self.copy_login_button.config(state="normal")

            # row number and password are should not be edited
            if self.column_selected != 0 and self.column_selected != 3:
                self.set_editable(True)
            else:
                self.set_editable(False)

        else:  # CELL UNSELECTED
            self.table.selection_remove(self.table.focus())
            self.delete_button.config(state="disabled")
            self.copy_password_button.config(state="disabled")
            self.copy_login_button.config(state="disabled")

            self.set_editable(False)

    def set_editable(self, state):
        """Function to enable/disable edit functions"""
        if state:
            self.edit_textbox.config(state="normal")
            self.edit_button.config(state="normal")
            self.edit_textbox.delete(1.0, "end")

            accounts_index = {1: 0,
                              2: 1,
                              4: 2}[self.column_selected]
            self.edit_textbox.insert("end", self.get_selected_values("all")[accounts_index])
        else:
            self.edit_textbox.delete(1.0, "end")
            self.edit_textbox.config(state="disabled")
            self.edit_button.config(state="disabled")

    def get_selected_values(self, column="all"):
        row = self.accounts[self.row_selected - self.start_index]
        # Return entire row
        if column == "all":
            return row
        # Return cell by selected row and column name
        else:
            lookup = {"service": 0, "login": 1, "notes": 2}
            return row[lookup[column]]

    def add_entry(self):
        """ Adds a new entry to the accounts list"""

        # Disable add button
        self.add_button.config(state="disabled")

        # Create popup window
        self.add_popup = tk.Tk()
        self.add_popup.title("Add entry")
        self.add_popup.resizable(False, False)
        self.popup = True

        def close_add_popup():
            self.add_button.config(state="normal")
            self.add_popup.destroy()
            self.popup = False

        self.add_popup.protocol("WM_DELETE_WINDOW", close_add_popup)

        tk.Label(self.add_popup, text="Service").grid(row=0, column=0, sticky="e", padx=(2, 2))
        tk.Label(self.add_popup, text="Login").grid(row=1, column=0, sticky="e", padx=(2, 2))
        tk.Label(self.add_popup, text="Notes").grid(row=2, column=0, sticky="ne", padx=(2, 2))

        service_entry = tk.Entry(self.add_popup)
        login_entry = tk.Entry(self.add_popup)
        notes_entry = tk.Text(self.add_popup, width=30, height=5)

        service_entry.grid(row=0, column=1, columnspan=3, sticky="we", padx=(2, 20))
        login_entry.grid(row=1, column=1, columnspan=3, sticky="we", padx=(2, 20))
        notes_entry.grid(row=2, column=1, columnspan=3, sticky="we", padx=(2, 20), pady=(2, 2))

        def add():
            service = service_entry.get()
            login = login_entry.get()
            notes = notes_entry.get(1.0, "end").replace("\n", " ")
            self.accounts.append([service, login, notes])
            service_entry.delete(0, "end")
            login_entry.delete(0, "end")
            notes_entry.delete(1.0, "end")
            self.update_table()

        tk.Button(self.add_popup, text="Add", command=add).grid(row=3, column=2, sticky="ew")

    def delete_entry(self):
        """ Deletes an entry from the accounts list"""
        del self.accounts[self.row_selected - self.start_index]
        self.update_table()
        self.set_editable(False)

    def edit_entry(self):
        """ Edits an entry from the accounts list"""
        accounts_index = {1: 0,
                          2: 1,
                          4: 2}[self.column_selected]
        self.accounts[self.row_selected - self.start_index][accounts_index] = \
            self.edit_textbox.get(1.0, "end").replace("\n", " ")
        self.update_table()

    def generate_password(self, service, login, masterkey):
        password_hash = sha256((service + login + masterkey).encode()).hexdigest()
        b64 = encode(decode(password_hash, 'hex'), 'base64').decode()
        return b64[:-2]  # Remove last two character, always =\n

    def copy_password(self):
        """ Copies password from selected row """
        self.clipboard_clear()
        self.clipboard_append(
                self.generate_password(self.get_selected_values("service"),
                                       self.get_selected_values("login"), self.password))
        self.master.update()

        def clear():
            """ Clears clipboard """
            sleep(5)
            self.clipboard_clear()
            self.clipboard_append("")
            self.update()

        thread = Thread(target=clear)
        thread.start()

    def copy_login(self):
        """ copies login from selected row """
        self.clipboard_clear()
        self.clipboard_append(self.get_selected_values("login"))
        self.update()

    def update_table(self):
        """ clears all stored entries in the table, refilling it with new values"""
        current_entries = self.table.get_children()
        self.start_index += len(current_entries)
        self.table.delete(*current_entries)
        # Add entries
        for index, row in enumerate(self.accounts):
            self.table.insert("", "end",
                              text=str(index + 1),
                              values=(row[0], row[1], "*****", row[2]))

    def logout(self):
        """ logs the user out and returns to the login page """
        self.master.server.send_message(("update", self.accounts))
        self.master.server.send_message(("logout",))
        if self.popup:
            self.add_popup.destroy()
        self.master.switch_frame(LoginPage)
        
    def delete_account(self):
        """ Creates a pop that deletes the users account"""
        if tk.messagebox.askokcancel("Confirm action", "Are you sure you want to delete your account?"):
            self.master.server.send_message(("delete_user",))
            self.master.switch_frame(LoginPage)

    def on_closing(self):
        """ sends updated table and closes the main window and popup """
        try:
            self.master.server.send_message(("update", self.accounts))
            self.master.server.send_message(("quit",))
        except OSError:  # Not connected
            pass
        self.master.server.close()
        if self.popup:
            self.add_popup.destroy()
        self.master.destroy()
        

PORT = clientconfig.connection["port"]
HOST = clientconfig.connection["host"]
BUFFER_SIZE = clientconfig.connection["buffer size"]

if __name__ == "__main__":
    ServerConnection()
