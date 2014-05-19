DHT protocol
============

Follows pretty much the principle of the torrent DHT: http://www.bittorrent.org/beps/bep_0005.html (READ IT)

But:
Vastly simplified packet format and encryption.

Boostrapping:
The first time you install the client we bootstrap it with a node. (bandwidth should not be a problem as the client only needs to be sent one reply.)


Basics
------
(All the numbers here are just guesses and are probably not optimal values)

client list: A list of node ids closest (mathematically see bittorrent doc) to ours matched with ip addresses + port number corresponding to that id and a timestamp containing the time or time since the client was successfully pinged.

"friends" list: A list containing the node_ids of all our "friends" or clients we want to connect to.
Also contains the ip addresses + port + node_ids + timestamp(of last ping like in the client list) of the 8 clients closest (mathematically see bittorrent doc) to each "friend"

One pinged lists: 
-One for storing a list of ips along with their ping_ids and a timestamp for the ping requests
Entries in the pinged lists expire after 5 seconds.
If one of the lists becomes full, the expire rate reduces itself one second or the new ping takes the place of the oldest one.


Entries in client list and "friends" list expire after 300 seconds without ping response.
Each client stores a maximum of 32 entries in its client list.
Each client in the client list and "friends" list is pinged every 60 seconds.
Each client in the client list and "friends" list has a timestamp which denote the last time it was successfully pinged.
If the corresponding clients timestamp is more than 130 seconds old it is considered bad.
Send a get nodes request every 20 seconds to a random good node for each "friend" in our "friends" list.
Send a get nodes request every 20 seconds to a random good node in the client list.


When a client receives any request from another
-----------------------------------------------
-Respond to the request
    -Ping request is replied to with with a ping response containing the same encrypted data
    -Get nodes request is replied with a send nodes reply containing the same encrypted data and the good nodes from the client list and/or the "friends" list that are closest to the requested_node_id

-If the requesting client is not in the client list:
    -If there are no bad clients in the list and the list is full:
        -If the id of the other client is closer (mathematically see bittorrent doc) than at least one of the clients in the list or our "friends" list:
            -Send a ping request to the client.
        -if not forget about the client.

    -If there are bad clients and/or the list isn't full:
        -Send a ping request to the client 

When a client receives a response
---------------------------------
-Ping response
    -If the node was previously pinged with a matching ping_id (check in the corresponding pinged list.)
        -If the node is in the client list the matching client's timestamp is set to current time.
        -If the node is in the "friends" list the matching client's timestamp is set to current time for every occurrence.
        -If the node is not in the client list:
            -If the list isn't full, add it to the list.
            -If the list is full, the furthest away (mathematically see bittorrent doc) bad client is replaced by the new one.
            -If the list is filled with good nodes replace the furthest client with it only if it is closer than the replaced node.
        -for each friend in the "friends" list:
            -If that friend's client list isn't full, add that client to it
            -If that friend's client list contains bad clients, replace the furthest one with that client.
            -If that friend's client list contains only good clients
                -If the client is closer to the friend than one of the other clients, it replaces the farthest one
                -If not, nothing happens.

    -Send nodes
        -If the ping_id matches what we sent previously (check in the corresponding pinged list.):
            -Each node in the response is pinged.





Protocol
--------

Node format: 
```
[uint8_t family (2 == IPv4, 10 == IPv6, 130 == TCP IPv4, 138 == TCP IPv6)][ip (in network byte order), length=4 bytes if ipv4, 16 bytes if ipv6][port (in network byte order), length=2 bytes][char array (node_id), length=32 bytes]
```
see also: DHT.h (pack_nodes() and unpack_nodes())

Valid queries and Responses:

Ping(Request and response): 
```
[byte with value: 00 for request, 01 for response][char array (client node_id), length=32 bytes][random 24 byte nonce][Encrypted with the nonce and private key of the sender: [1 byte type (0 for request, 1 for response)][random 8 byte (ping_id)]]
```
ping_id = a random integer, the response must contain the exact same number as the request


Get nodes (Request):
Packet contents: 
```
[byte with value: 02][char array (client node_id), length=32 bytes][random 24 byte nonce][Encrypted with the nonce and private key of the sender:[char array: requested_node_id (node_id of which we want the ip), length=32 bytes][Sendback data (must be sent back unmodified by in the response), length=1 to NODES_ENCRYPTED_MESSAGE_LENGTH bytes]]
```
Valid replies: a send_nodes packet

Send_nodes (response (for all addresses)): 
```
[byte with value: 04][char array  (client node_id), length=32 bytes][random 24 byte nonce][Encrypted with the nonce and private key of the sender:[uint8_t number of nodes in this packet][Nodes in node format, length=?? * (number of nodes (maximum of 8 nodes)) bytes][Sendback data, length=1 to NODES_ENCRYPTED_MESSAGE_LENGTH bytes]]
```
