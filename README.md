# password manager
The repository contain a server and client program for a Client-Server password manager implemented in python. It was produced for a A-Level school project and therefore not remotely secure.

**DISCLAIMER:  This password manager is not secure. Do not use genuinely.**

## HOW TO USE

1. Configure server config file to your requirements. If you wish to have it accessable across networks 
you will have to port forward and use the same port in the config file.
1. Then you run the server/server.py on a computer.
2. Write down the ip address it is hosted at.
3. Insert the host address and port in the clientconfig.ini.
4. Run client/client.py and use however desired

## HOW IT WORKS
All communication is currently encrypted (using a vernam cipher and weird Diffie-Hellman key).
When you login in to the service, the password is hashed with a salt so your password can't be recovered. But can easily be MiTM attacked. 

One quirk with this program is that specific pre-existing passwords cannot be stored, but a relatively secure system can be used to generate passwords that proves difficult for attackers to thwart even if the database was compromised.

Passwords are generated from a SHA256 hash of the service, login and your masterkey(login password). No passwords are stored anyway, but are in fact generated on every access so there is no storage device where they can be compromised.
Only the service, login information and the notes information are sent to the server. The server (and thus any attackers) don't know the unhashed password and so only the client should be able to generate the passwords.

This does mean that editing an entry will change the password generated so don't change your passwords until you've confirmed the entered information is correct.


TECHNICAL NOTES
- Uses the PORT 33000 by default
