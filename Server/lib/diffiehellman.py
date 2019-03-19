from os import urandom

"""
This module is used for the calculations for a Diffie-Hellman key exchange
this implementation uses the prime and generator described by the
4096-bit MODP Group id 16
Information available at: https://tools.ietf.org/html/rfc3526#section-5
"""


class DiffieHellman:

    def __init__(self):
        self.generator = 2
        self.prime = 0xFFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD129024E088A67CC74020BBEA63B139B22514A08798E3404DDEF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7EDEE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3DC2007CB8A163BF0598DA48361C55D39A69163FA8FD24CF5F83655D23DCA3AD961C62F356208552BB9ED529077096966D670C354E4ABC9804F1746C08CA18217C32905E462E36CE3BE39E772C180E86039B2783A2EC07A28FB5C55DF06F4C52C9DE2BCBF6955817183995497CEA956AE515D2261898FA051015728E5A8AACAA68FFFFFFFFFFFFFFFF
        self.key_size = 8  # bytes
        self.key = int.from_bytes(urandom(self.key_size), byteorder="big")

    def get_public_key(self):
        return pow(self.generator, self.key, self.prime)

    def get_shared_key(self, public_key):
        return pow(public_key, self.key, self.prime)

