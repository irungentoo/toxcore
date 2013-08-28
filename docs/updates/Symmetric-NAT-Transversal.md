Notes:

Friend requests need to be routed.

The current DHT should be capable of punching all NATs except symmetric ones.

######

Symmetric NAT hole punching:

If we are not connected to the friend and if the DHT is queried and ips 
returned for the friend are the same but the port is different, the friend is 
assumed to be behind a symmetric NAT.

Before attempting the procedure we first send a routed ping request to the 
friend. This request is to be routed through the nodes who returned the ip of 
the peer.

As soon as we receive one routed ping request from the other peer, we respond 
with a ping response. 

Ping request/response packet:
See: Crypto request packets in [[Crypto]]

Message:
For the ping request:
[char with a value of 254][char with 0][8 byte random number]

For the ping response:
[char with a value of 254][char with 1][8 byte random number (The same that was sent in the request)]

As soon as we get a proper ping response from the other we run the different 
ports returned by the DHT through our port guessing algorithm.

######

Port guessing algorithm:

Right now it just tries all the ports directly beside the known ports.(A better one is needed)

######

We send DHT ping requests to all the guessed ports, only a couple at a time.
