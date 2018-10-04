# password-manager
server and gui based client program for a password manager in python.

This was produced for my coursework for AQA A-Level project.

DISCLAIMER
This is not professional don't actually use this to store passwords as I cannot assure that this is secure against any modern methods
of hacking... bla bla bla you get the point

HOW TO USE

1. You run the server/server.py on a computer
2. Write down the ip address it is hosted at
3. Insert the host address and port in the clientconfig.ini
4. Run client/client.py and use however bloody ever

HOW IT WORKS
All communication is currently encrypted and is sent in plaintext.
When you login in to the service, the password is hashed with a salt so your password can't be recovered. Assuming you reuse, which you shouldn't

Passwords are generated from a SHA256 hash of the service, login and your masterkey(login password).
Only the service, login and the notes information are sent to the server thus only the client should be able to generate the passwords.



TECHNICAL NOTES
- Might not work for not LAN might need to do some port-forwarding
- Uses the PORT 33000
