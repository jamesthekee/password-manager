from hashlib import sha256
from codecs import encode, decode

"""
Defines function used by client to generate passwords
"""


def generate_password(service, login, masterkey):
    """ Generate a password by concatenating the strings and hashing them. """
    password_hash = sha256((service + login + masterkey).encode()).hexdigest()
    b64 = encode(decode(password_hash, 'hex'), 'base64').decode()
    return b64[:-2]  # Remove last two character, always =\n

