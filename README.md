![Project Tox](https://rbt.asia/boards/g/img/0352/79/1373823047559.png "Project Tox")
Project Tox, _also known as Tox_, is a FOSS instant messaging application aimed to replace Skype.<br />

With the rise of governmental monitoring programs, Tox aims to be an easy to use application that allows people to connect with friends and loved ones without the worry of privacy.<br /> <br />




**IRC**: #InsertProjectNameHere on Freenode, alternatively, you can use the [webchat](https://webchat.freenode.net/).<br />
**Website**: [http://tox.im](http://tox.im)

**Website translations**: [see stal888's repository](https://github.com/stal888/ProjectTox-Website)<br/>
**Qt GUI**: [see nurupo's repository](https://github.com/nurupo/ProjectTox-Qt-GUI)



## The Complex Stuff:
+ Tox must use UDP simply because you can't hole punch with TCP. It's possible, but it doesn't work all the time.
+ Every peer is represented as a byte string (the public key of the peer [client id])
+ We're using torrent-style DHT so that peers can find the IP of the other peers when they have their ID.
+ Once the client has the IP of that peer, they start initiating a secure connection with each other. (See [Crypto](https://github.com/irungentoo/ProjectTox-Core/wiki/Crypto)
+ When both peers are securely connect with the encryption, they can securely exchange messages, initiate a video chat, send files, etc.<br />
+ Current build status: [![Build Status](https://travis-ci.org/irungentoo/ProjectTox-Core.png?branch=master)](https://travis-ci.org/irungentoo/ProjectTox-Core) 

## Roadmap:
- [x] Get our DHT working perfectly.(Done, needs large scale testing though.)
- [x] Reliable connection (See Lossless_UDP protocol) to other peers according to client id. (Done, see DHT_sendfiletest.c for an example)
- [x] Encryption. (Done)
- [ ] Get a simple text only im client working perfectly. (This is where we are)
- [ ] Streaming media
- [ ] ???

For further information, check our [To-do list](https://github.com/irungentoo/ProjectTox-Core/wiki/TODO)


### Important-stuff:

Use the same UDP socket for everything

Keep everything really simple.

### Details and Documents:

[DHT Protocol](https://github.com/irungentoo/ProjectTox-Core/wiki/DHT)<br />
[Lossless UDP Protocol](https://github.com/irungentoo/ProjectTox-Core/wiki/Lossless-UDP)<br />
[Crypto](https://github.com/irungentoo/ProjectTox-Core/wiki/Crypto)<br />
[Ideas](https://github.com/irungentoo/ProjectTox-Core/wiki/Ideas)

### Why are you doing this? There are already a bunch of free skype alternatives.
The goal of this project is to create a configuration-free p2p skype 
replacement. Configuration-free means that the user will simply have to open the program and 
without any account configuration will be capable of adding people to his 
friends list and start conversing with them. There are many so called skype replacements and all of them are either hard to 
configure for the normal user or suffer from being much too centralized.
