from hashlib import sha256
from codecs import encode, decode


def generate_password(service, login, masterkey):
    password_hash = sha256((service + login + masterkey).encode()).hexdigest()
    b64 = encode(decode(password_hash, 'hex'), 'base64').decode()
    return b64[:-2]  # Remove last two character, always =\n

