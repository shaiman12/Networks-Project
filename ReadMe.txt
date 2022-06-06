NIS Assignment 
ARNSHA011, FSHJAR002, SNDJEM001, RSNJOS005

This application implements a UDP client-server group chat. 
All messages are encrypted using PGP as our encryption scheme. 

To run this program follow these steps:
1) First type "make clean" followed by "make" into your command line
2) To run an instance of the server:
	2a) If you wish to run the clients and servers locally type: "make runServerLocal"
	2b) If you wish to run the clients and servers over the internet type: "make runServerWAN"
	
3) To run instances of the client you are required to match the local/WAN option that you selected for your server. You can also choose to display all the debug statements involved in encryption/decryption. The debug statements will be shown on any of the receiver clients. You may run as many clients as you wish. Use the following commands to run your client instances
	3a) If you wish to run the clients and servers locally type: "make runClientLocal"
	3b) If you wish to run the clients and servers locally, with debug statements type:
 	"make runClientLocal_debug"
	3c) If you wish to run the clients and servers over the internet type: 
	"make runClientWAN"
	3d) If you wish to run the clients and servers over the internet, with debug statements type: 
	"make runClientWAN_debug"
4) You can view and edit the whitelisted usernames in the whitelist.txt 
	Please use a username listed here to login to a client instance
 
NOTE: Running our program over the internet only works when the server is run on FSHJAR002's computer as an external connection (i.e. over WAN) requires the inclusion of port forwarding to be setup in advance. In addition, the IP addresses that are used for this WAN setup are unique to FSHJAR002's computer and router. Please contact FSHJAR002@myuct.ac.za if you wish to test this feature. You can
alternatively, change the IP address inline in the code
