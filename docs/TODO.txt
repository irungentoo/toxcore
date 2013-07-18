Things to do now:

-Network protocol (Done)

-Figure out the best way to do "lossless" UDP. (Done)

-Start work on the im protocol.(simple im part pretty much done)

-Start coding the gui (In Progress (Using Qt5))

-Get a basic im client working using the now completed DHT implementation to find the ips of your friends.

-Find some good encryption libraries.(Done)
    we will use: http://nacl.cr.yp.to/

-Add NaCl to our build system.

-Make NaCl work on windows (DONE)
    https://github.com/jedisct1/libsodium
    

-Crypto (Done (needs testing))

-Harden the DHT (Research in progress)

-Find and fix bugs in the code.

Things to do later:

-Figure out the whole sound and video transmission. (encrypted and fast)

-File transfer (encrypted and fast)

Less important.

-Symmetric NATs
    No UDP hole punching on them so we need to do something else 
    (only if both the clients which try to connect to themselves are behind one)


-Decentralized IRC like channels (chatrooms).



-Offline messaging protocol (text only)
    Use your friends.(or maybe the people closest (mathematically by comparing client_id's) to you or the friend you want to send the message to).
    The message will not be very big. Lets say we limit the maximum number of bytes for one to 1024, it means if every client stores 1024 offline messages it only takes 1 MB of ram.

-IPv6
    Currently the core only supports ipv4
    
