import sqlite3
from os import urandom
from binascii import hexlify

conn = sqlite3.connect("registered_accounts.db", check_same_thread=False)
cursor = conn.cursor()

cursor.execute("CREATE TABLE IF NOT EXISTS registered_accounts(username STRING, passwordhash STRING, salt STRING)")
conn.commit()


def username_exists(username):
    cursor.execute("SELECT * FROM registered_accounts where username=?", (username,))
    login_details = cursor.fetchone()
    return bool(login_details)


def get_salt(username):
    cursor.execute("SELECT * FROM registered_accounts where username=?", (username,))
    return cursor.fetchone()[2]


def verify_hash(username, received_hash):
    cursor.execute("SELECT * FROM registered_accounts where username=?", (username,))
    stored_hash = cursor.fetchone()[1]
    return received_hash == stored_hash


def add(username, password_hash, salt):
    cursor.execute("INSERT INTO registered_accounts VALUES (?, ?, ?)", (username, password_hash, salt))
    conn.commit()


def generate_salt():
    return hexlify(urandom(16)).decode()


def delete_user(username):
    cursor.execute("DELETE FROM registered_accounts WHERE username=?", (username,))
    conn.commit()


