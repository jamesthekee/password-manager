# password-manager
The files contain a server and client program for a password manager implemented in python. 

This was produced for my coursework for AQA A-Level project.

DISCLAIMER
This is not a professional product do not use this to store real passwords, this is merely a fake product and is for my own educational purpose. None of the encryption or security precautions are of industry standard. 

HOW TO USE

1. Configure server config file to your requirements. If you wish to have it accessable across networks 
you will have to port forward and use the same port in the config file.
1. Then you run the server/server.py on a computer.
2. Write down the ip address it is hosted at.
3. Insert the host address and port in the clientconfig.ini.
4. Run client/client.py and use however bloody ever

HOW IT WORKS
All communication is currently encrypted(using vernam cipher) and is sent in plaintext.
When you login in to the service, the password is hashed with a salt so your password can't be recovered. 

In this application you cannot store associated passwords with usernames amd they are only generated from your information.

Passwords are generated from a SHA256 hash of the service, login and your masterkey(login password).
Only the service, login and the notes information are sent to the server thus only the client should be able to generate the passwords.

This does mean that editing an entry will change the password generated so don't change your passwords until you've confirmed the entered information is correct.


TECHNICAL NOTES
- Uses the PORT 33000 by default
