from codecs import encode, decode
from hashlib import sha256

"""
password generation process
write down service name, login name and your masterkey down perfectly without a difference in casing or spacing
concatenate them toghet in the order of service, login, masterkey
pass through sha256 hash function
convert from hex to base 64 
remove the = symbol from the end from paddinG
"""

def generate_password(service, login, masterkey):
    """generates password from the clients service, login, masterkey"""
    password_hash = sha256((service + login + masterkey).encode()).hexdigest()
    b64 = encode(decode(password_hash, 'hex'), 'base64').decode()
    return b64[:-2]  # remove last two character, always =\n


if __name__ == "__main__":
    print("This is a service to generate/ get passwords without the need to login ")
    service = input("Please enter the service name: ")
    login = input("Please enter login: ")
    masterkey = input("Please enter your masterkey(login password): ")
    print(generate_password(service, login, masterkey))
