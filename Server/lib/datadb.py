import sqlite3
import os


def initialize(directory):
    """ Initialize variables for use in the module. """
    # Check if directory exists and create folders
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


def close():
    """ Closes handlers for the database. """
    conn.close()
    cursor.close()


class SQLInjectionRiskError(Exception):
    pass


class DatabaseInterface:
    """ Object that handles the changes to the database for a user. """

    def __init__(self, username):
        if username.isalnum():
            self.username = username
            cursor.execute("CREATE TABLE IF NOT EXISTS {}(service STRING, login STRING, notes STRING)".format(username))
        else:
            raise SQLInjectionRiskError("System attempted to create non-alphabetical username: {}".format(username))

    def get_accounts(self):
        """ Returns list of all account data in the database. """

        cursor.execute("SELECT service, login, notes  FROM {}".format(self.username))
        return cursor.fetchall()

    def add_entry(self, service, login, notes):
        """ Adds account to the database"""

        cursor.execute("INSERT INTO {} VALUES (?, ?, ?)".format(self.username), (service, login, notes))
        conn.commit()

    def delete_user(self):
        """ Deletes all recorded user information. """

        cursor.execute("DROP TABLE IF EXISTS {}".format(self.username))
        conn.commit()

    def update_table(self, accounts):
        """ Replaces the current table with newer one. """

        cursor.execute("DELETE FROM {}".format(self.username))
        for row in accounts:
            cursor.execute("INSERT INTO {} VALUES (?, ?, ?)".format(self.username), row)
        conn.commit()

    def view_data(self):
        """ Shows the data via print statement, debugging only. """

        accounts = self.get_accounts()
        if len(accounts) != 0:
            print("   service        |login          |notes")
            print("-"*75)
            for index, line in enumerate(accounts):
                print("{:>2}|{:15}|{:15}|{:15}".format(index+1, line[1], line[2], line[3]))
            print()
        else:
            print("No information registered with this account")


