Tox
===

Current IRC: #InsertProjectNameHere
on Freenode or [webchat](https://webchat.freenode.net/)


Proposal of a free as in freedom skype replacement:

## Basics:

UDP must be used for everything simply because you can't do hole punching with TCP (well you can but it doesn't work all the time)
    
Every peer is represented as a byte string (the client id) (it is the hash (SHA-256?) of the public key of the peer). (if you want to add someone you need that id (either ask that person directly or maybe through some kind of search engine?))
    
Use something torrent DHT style so that peers can find the ip of the other peers when they have their id.
    
Once the client has the ip of that peer they start initiating a secure connection with each other.(asymmetric encryption(RSA?)  is used to encrypt the session keys for the symmetric(AES?) encryption so that they are exchanged securely) 
(We can't use public key encryption for everything it's too fucking slow) man in the middle attacks are avoided because the id is the hash of the public key (the client can be sure it's legit.)
    
When both peers are securely connected with the encryption(AES?) they can securely exchange messages, initiate a video chat, send files, etc...
    
Your client stores the id of the peers along with their public keys used to initiate the connection (this is your contacts list)

## Roadmap:

1. Get our DHT working perfectly.(Done, needs large scale testing though.)
2. Reliable connection (See Lossless_UDP protocol) to other peers according to client id.
3. Encrypted message sending with RSA (NOTE: We have not decided on the encryption yet. This was just a quick guess.)
4. Encrypted message sending with AES (encryption done)
5. Reliable encrypted sending of data larger than the maximum packet size.
...

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