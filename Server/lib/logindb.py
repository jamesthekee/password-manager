import sqlite3
import os
from binascii import hexlify


def initialize(directory):
    """ Initialize variables for use in the module. """

    # Create directory
    if "/" in directory:
        # Remove the file name
        index = len(directory) - 1 - directory[::-1].index("/")
        temp = directory[:index]
        print(temp)
        if not os.path.exists(temp):
            os.makedirs(temp)

    global conn, cursor
    conn = sqlite3.connect(directory, check_same_thread=False)
    cursor = conn.cursor()
    cursor.execute("CREATE TABLE IF NOT EXISTS registered_accounts(username STRING, passwordhash STRING, salt STRING)")
    conn.commit()


def close():
    """ Closes handlers for the database. """

    conn.close()
    cursor.close()


def username_exists(username):
    """ Returns true if username is in database. """

    cursor.execute("SELECT * FROM registered_accounts where username=?", (username,))
    login_details = cursor.fetchone()
    return bool(login_details)


def get_salt(username):
    """ Returns the username's salt. """

    cursor.execute("SELECT * FROM registered_accounts where username=?", (username,))
    return cursor.fetchone()[2]


def verify_hash(username, received_hash):
    """ Returns true if the hash is correct. """

    cursor.execute("SELECT * FROM registered_accounts where username=?", (username,))
    stored_hash = cursor.fetchone()[1]
    return received_hash == stored_hash


def add(username, password_hash, salt):
    """ Adds a user to the database. """

    cursor.execute("INSERT INTO registered_accounts VALUES (?, ?, ?)", (username, password_hash, salt))
    conn.commit()


def generate_salt():
    """Returns a 32 byte hexadecimal salt"""

    return hexlify(os.urandom(16)).decode()


def delete_user(username):
    """ Deletes a user from the database. """

    cursor.execute("DELETE FROM registered_accounts WHERE username=?", (username,))
    conn.commit()


