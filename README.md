![Project Tox](https://raw.github.com/irungentoo/ProjectTox-Core/master/other/tox.png "Project Tox")
***

With the rise of governmental monitoring programs, Tox, a FOSS initiative, aims to be an easy to use, all-in-one communication platform that ensures their users full privacy and secure message delivery.<br /> <br />

[**Website**](https://tox.im) **|** [**Wiki**](http://wiki.tox.im/) **|** [**Blog**](https://blog.libtoxcore.so/) **|** [**FAQ**](http://wiki.tox.im/FAQ) **|** [**Binaries**](http://download.tox.im/) **|** [**Clients**](http://wiki.tox.im/Client) **|** [**Compiling**](http://wiki.tox.im/Installing) **|** [**API**](http://api.libtoxcore.so/) **|** [**Qt-GUI**](https://github.com/nurupo/ProjectTox-Qt-GUI) **|** **IRC:** #tox@freenode


## The Complex Stuff:
### UDP vs. TCP
Tox must use UDP simply because [hole punching](http://en.wikipedia.org/wiki/UDP_hole_punching) with TCP is not as reliable.

But for people who under bad firewall, tox must use TCP relays [How it's going to work](https://github.com/irungentoo/ProjectTox-Core/blob/master/docs/TCP_Network.txt)

### Connecting & Communicating
Every peer is represented as a [byte string][String] (the public key [Tox ID] of the peer). By using torrent-style DHT, peers can find the IP of other peers by using their Tox ID. Once the IP is obtained, peers can initiate a [secure](https://github.com/irungentoo/ProjectTox-Core/wiki/Crypto) connection with each other. Once the connection is made, peers can exchange messages, send files, start video chats, etc. using encrypted communications.


**Current build status:** [![Build Status](https://travis-ci.org/irungentoo/ProjectTox-Core.png?branch=master)](https://travis-ci.org/irungentoo/ProjectTox-Core)


## Q&A:

### What are your goals of Tox?

We want Tox to be as simple as possible while remaining as secure as possible.

### Why are you doing this? There are already a bunch of free Skype alternatives.
The goal of this project is to create a configuration-free P2P Skype replacement. Configuration-free means that the user will simply have to open the program and without any account configuration will be capable of adding people to his or her's friends list and start conversing with them. There are many so-called Skype replacements and all of them are either hard to configure for the normal user or suffer from being way too centralized.

## TODO:
- [TODO](/docs/TODO)


## Documentation:

- [Installation](/INSTALL.md)
- [DHT Protocol](http://wiki.tox.im/index.php/DHT)<br />
- [Lossless UDP Protocol](http://wiki.tox.im/index.php/Lossless_UDP)<br />
- [Crypto](http://wiki.tox.im/index.php/Crypto)<br />
- [Ideas](http://wiki.tox.im/index.php/Ideas)

[String]: https://en.wikipedia.org/wiki/String_(computer_science)
