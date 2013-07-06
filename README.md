Tox
===

Current IRC: #InsertProjectNameHere
on Freenode or [webchat](https://webchat.freenode.net/)


Proposal of a free as in freedom skype replacement:

## Basics:

UDP must be used for everything simply because you can't do hole punching with TCP (well you can but it doesn't work all the time)
    
Every peer is represented as a byte string (the client id) (It is the public key of the peer.). (if you want to add someone you need that id (either ask that person directly or maybe through some kind of search engine?))
    
Use something torrent DHT style so that peers can find the ip of the other peers when they have their id.
    
Once the client has the ip of that peer they start initiating a secure connection with each other.(See Crypto.)
    
When both peers are securely connected with the encryption they can securely exchange messages, initiate a video chat, send files, etc...
    
Your client stores the public keys/id of the peers used to initiate the connection (this is your contacts list)

## Roadmap:

1. Get our DHT working perfectly.(Done, needs large scale testing though.)
2. Reliable connection (See Lossless_UDP protocol) to other peers according to client id. (Done, see DHT_sendfiletest.c for an example)
3. Encryption. (Done)
4. Get a simple text only im client working perfectly. (This is where we are)
5. Streaming media
6. 

## TODO:
    
See: [docs/TODO.txt](https://github.com/irungentoo/InsertProjectNameHere/blob/master/docs/TODO.txt)

### Important-stuff:

Use the same UDP socket for everything

Keep everything really simple.

### Details:

DHT protocol:
    see: [docs/DHT.txt](/docs/DHT.txt)
    
Lossless UDP protocol:
    Either we find one with an already working implementation (Didn't find a good implementation, writing my own)
    see also: [docs/Lossless_UDP.txt](/docs/Lossless_UDP.txt)

Crypto:
    see: [docs/Crypto.txt](/docs/Crypto.txt)

### Why are you doing this? There are already a bunch of free skype alternatives.

see: [docs/WHY.txt](/docs/WHY.txt)
