# Chat-Server-Client
A C based chat server and client.

There are two sides of the code. One is the chat `server` side and the other is `client` side which connects to the chat server. Multiple clients can connect to the same server. There are multiple features to the chat application like admin, kicking user, sending emoticons, etc. 

# How to install the chat application
Clone the git repository. After cloning, open two terminal windows(in Mac) or Cmd Prompt(in Windows). In any one of them, compile the code simply by calling `make`. Once the code is compiled, the chat server and client is setup. 

Now before running the client, we need to setup the server. This can simply be done by calling `./chat_server` in one of the terminal window. One the server is setup, clients can now connect to the server and start chatting. Again, this can be done by calling `./chat_client` in the command line.

# How to use the chat application
Once both the chat server and various clients are setup, we can start chatting. 

In order to send a `normal message`, a client can simply type the message in the terminal and send it. On the backend, the server will`receive` the message and `echo` it to all the clients connected to the server. 

In order to send an `emoticon`, one needs to send the message in the following format: `.e name-of-emote`. For example, `.e lul` will be sent as described in the picture below. 
Note: Only the emote images present in the `emotes` folder will be sent.
![Imgur](https://imgur.com/a2wuOWU)


In order to kick a user, one needs to send the message in the following format: `.k username`. Only `admin` has the privilege to kick any user. Admin is the first ever client connected to the server. In case, the admin decides to kick itself, then the user who joined after admi, becomes the new admin. Any kick command from a non-admin user will simply be ignored.
A sample usage of the kick command can be seen in the picture above. 

# Extend the code
Currently the code only runs locally on one machine. This can simply be improved by allowing client to specify `port` and `host address` in the command line.  This can be edited in `chat_client.c`. 

Additionally, there are many more features that can added like 'status', 'profile picture', 'availability status', etc. These features were out of scope for this project currently. 

# License Information

Copyright © 2020 akshitgoyal - All Copy Rights Are Reserved.

Some small chunk of the code has been provided to me as starter code by the instructors of CSC209 Winter 2020 at the University of Toronto Mississauga. They hold the complete right over that part of the code and one needs a permission from them to use it. 
