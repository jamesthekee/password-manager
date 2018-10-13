import lib.generate as generate

"""
password generation process
write down service name, login name and your masterkey down perfectly without a difference in casing or spacing
concatenate them toghet in the order of service, login, masterkey
pass through sha256 hash function
convert from hex to base 64 
remove the = symbol from the end from padding
"""


if __name__ == "__main__":
    print("This is a service to generate/ get passwords without the need to login ")
    service = input("Please enter the service name: ")
    login = input("Please enter login: ")
    masterkey = input("Please enter your masterkey(login password): ")
    print(generate.generate_password(service, login, masterkey))
