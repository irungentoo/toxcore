Tox
===

Current IRC: #InsertProjectNameHere
on freenode or https://webchat.freenode.net/


Proposal of a free as in freedom skype replacement:

--------Basics--------:

    -UDP most be used for everything simply because you can't do hole punching with TCP (well you can but it doesn't work all the time)
    
    -Every peer is represented as a byte string (the client id) (it is the hash (SHA-256 ?) of the public key of the peer). (if you want to add someone you need that id.)
    
    -Use something torrent DHT style so that peers can find the ip of the other peers when they have their id.
    
    -Once the client has the ip of that peer they start initiating a secure connection with each other.(asymmetric encryption(RSA?)  is used to encrypt the session keys for the symmetric(AES?) encryption so that they are exchanged securely) 
    (We can't use public key encryption for everything it's too fucking slow) man in the middle attacks are avoided because the id is the hash of the public key (the client can be sure it's legit.)
    
    -When both peers are securely connected with AES they can securely exchange messages, initiate a video chat, send files, etc...
    
    -Your client stores the id of the peers along with their public keys used to initiate the connection (this is your contacts list)

-------Roadmap------:

    1.Get our DHT working perfectly.
    2.Connection to other peers according to client id.
    3.Encrypted message sending with RSA
    4.Encrypted message sending with AES (encryption done)
    5.Reliable sending of data larger than the maximum packet size.
    ...

-------Important-stuff--:

    Use the same UDP socket for everything

-------Details---------:

    DHT protocol:
        Follows pretty much the principle of the torrent DHT: http://www.bittorrent.org/beps/bep_0005.html (READ IT)
    
        But:
            Vastly simplified packet format.
            
        Boostrapping:
            The first time you install the client
        
    
        Basics (All the numbers here are just guesses and are probably not optimal values):
        
            client list: A list of node ids closest (mathematically see bittorrent doc) to ours matched with ip addresses + port number corresponding to that id and a timestamp containing the time or time since the client was successfully pinged.
            
            "friends" list: A list containing the node_ids of all our "friends" or clients we want to connect to.
                            Also contains the ip addresses + port + node_ids + timestamp(of last ping like in the client list) of the 8 clients closest (mathematically see bittorrent doc) to each "friend"
      
            Entries in client list and "friends" list expire after 300 seconds without ping response.
            Each client stores a maximum of 32 entries in its client list.
            Each client in the client list and "friends" list is pinged every 60 seconds.
            Each client in the client list and "friends" list has a timestamp which denote the last time it was successfully pinged.
            If the corresponding clients timestamp is more than 130 seconds old it is considered bad.
            Send a get nodes request every 20 seconds to a random good node for each "friend" in our "friends" list.
            Send a get nodes request every 20 seconds to a random good node in the client list.
    
    
            When a client receives any request from another:
              -Respond to the request
                  -Ping request is replied to with with a ping response containing the same ping_id
                  -Get nodes request is replied with a send nodes reply containing the same ping_id and the good nodes from the client list and/or the "friends" list that are closest to the requested_node_id
    
              -If the requesting client is not in the client list:
                -If there are no bad clients in the list and the list is full:
                        -If the id of the other client is closer (mathematically see bittorrent doc) than at least one of the clients in the list or our "friends" list:
                            -Send a ping request to the client.
                        -if not forget about the client.
    
                -If there are bad clients and/or the list isn't full:
                        -Send a ping request to the client 
    
            When a client receives a response:
                -Ping response
                    -If the node was previously pinged with a matching ping_id
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
                    -If the ping_id matches what we sent previously:
                        -Each node in the response is pinged.
              
    
            
            
    
        Protocol:
    
            Node format: [char array (node_id), length=32 bytes][ip (in network byte order), length=4 bytes][port (in network byte order), length=2 bytes]
    
            Valid queries and Responses:
    
                Ping(Request and response): [byte with value: 00 for request, 01 for response][random 4 byte (ping_id)][char array (client node_id), length=32 bytes]
                    ping_id = a random integer, the response must contain the exact same number as the request
    
    
                Get nodes (Request):
                Packet contents: [byte with value: 02][random 4 byte (ping_id)][char array (client node_id), length=32 bytes][char array: requested_node_id (node_id of which we want the ip), length=32 bytes]
                Valid replies: a send_nodes packet
    
                Send_nodes (response): [byte with value: 03][random 4 byte (ping_id)][Nodes in node format, length=40 * (number of nodes (maximum of 8 nodes)) bytes]
                ex: 03[Node][Node][Node] 

