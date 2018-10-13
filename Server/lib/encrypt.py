from hashlib import sha256

""" 
Module that defines function for encryption, 
which performs a vernam cipher on the message and a key. This key is generated from seed and all
seeds are derived from the previous seed, with the original being the shared Diffie-Hellman key. 
"""


def encrypt(message, seed):
    """ Perform vernam cipher on message using key generated from seed. """

    key = int(sha256(seed.encode()).hexdigest(), 16)
    seed = str(key)
    key = bin(key)[2:]

    # Concatenate all bytes in message to create binary string
    message_binary = ""
    for byte in message:
        message_binary = "{:0>8}".format(bin(byte)[2:]) + message_binary

    # Ensure key length is sufficient
    while len(key) < len(message_binary):
        seed_hash = int(sha256(seed.encode()).hexdigest(), 16)
        seed = str(seed_hash)
        key += bin(seed_hash)[2:]

    # Trim key to exact length of message
    key = key[:len(message_binary)]

    # Perform xor on key and message
    vernam = bin(int(key, 2) ^ int(message_binary, 2))[2:]
    if len(vernam) % 8 != 0:
        vernam = (8 - (len(vernam) % 8)) * '0' + vernam

    # Convert vernam cipher into bytes object
    bytelist = []
    for i in range(0, len(vernam), 8):
        byte = int(vernam[i: i + 8], 2)
        bytelist = [byte] + bytelist

    return bytes(bytelist), seed
