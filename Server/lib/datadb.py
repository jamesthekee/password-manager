import sqlite3
import os




def initialize(directory):
    global conn, cursor
    print(directory)
    conn = sqlite3.connect(directory, check_same_thread=False)
    cursor = conn.cursor()


def close():
    conn.close()
    cursor.close()


class DatabaseInterface:

    def __init__(self, username):
        self.username = username
        cursor.execute("CREATE TABLE IF NOT EXISTS {}(service STRING, login STRING, notes STRING)".format(username))

    def get_accounts(self):
        cursor.execute("SELECT service, login, notes  FROM {}".format(self.username))
        return cursor.fetchall()

    def add_entry(self, service, login, notes):
        cursor.execute("INSERT INTO {} VALUES (?, ?, ?)".format(self.username), (service, login, notes))
        conn.commit()

    def delete_user(self):
        cursor.execute("DROP TABLE IF EXISTS {}".format(self.username))
        conn.commit()

    def update_table(self, accounts):
        cursor.execute("DELETE FROM {}".format(self.username))
        for row in accounts:
            cursor.execute("INSERT INTO {} VALUES (?, ?, ?)".format(self.username), row)
        conn.commit()

    def view_data(self):
        """ For testing and debugging only"""
        accounts = self.get_accounts()
        if len(accounts) != 0:
            print("   service        |login          |notes")
            print("-"*75)
            for index, line in enumerate(accounts):
                print("{:>2}|{:15}|{:15}|{:15}".format(index+1, line[1], line[2], line[3]))
            print()
        else:
            print("No information registered with this account")


