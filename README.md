![Project Tox](https://raw.github.com/irungentoo/toxcore/master/other/tox.png "Project Tox")
***

With the rise of government surveillance programs, Tox, a FOSS initiative, aims to be an easy to use, all-in-one communication platform that ensures full privacy and secure message delivery.<br /> <br />

[**Website**](https://tox.chat) **|** [**Wiki**](https://wiki.tox.chat/) **|** [**Blog**](https://blog.tox.chat/) **|** [**FAQ**](https://wiki.tox.chat/doku.php?id=users:faq) **|** [**Binaries/Downloads**](https://wiki.tox.chat/Binaries) **|** [**Clients**](https://wiki.tox.chat/doku.php?id=clients) **|** [**Compiling**](/INSTALL.md)

**IRC Channels:** [#tox@freenode](https://webchat.freenode.net/?channels=tox), [#tox-dev@freenode](https://webchat.freenode.net/?channels=tox-dev)


## The Complex Stuff:
### UDP vs. TCP
Tox must use UDP simply because [hole punching](https://en.wikipedia.org/wiki/UDP_hole_punching) with TCP is not as reliable.
However, Tox does use [TCP relays](/docs/TCP_Network.txt) as a fallback if it encounters a firewall that prevents UDP hole punching.

### Connecting & Communicating
Every peer is represented as a [byte string](https://en.wikipedia.org/wiki/String_(computer_science)) (the public key [Tox ID] of the peer). By using torrent-style DHT, peers can find the IP of other peers by using their Tox ID. Once the IP is obtained, peers can initiate a [secure](/docs/updates/Crypto.md) connection with each other. Once the connection is made, peers can exchange messages, send files, start video chats, etc. using encrypted communications.


**Current build status:** [![Build Status](https://travis-ci.org/irungentoo/toxcore.png?branch=master)](https://travis-ci.org/irungentoo/toxcore)


## Q&A:

### What are your goals with Tox?

We want Tox to be as simple as possible while remaining as secure as possible.

### Why are you doing this? There are already a bunch of free Skype alternatives.
The goal of this project is to create a configuration-free P2P Skype replacement. “Configuration-free” means that the user will simply have to open the program and will be capable of adding people and communicating with them without having to set up an account. There are many so-called Skype replacements, but all of them are either hard to configure for the normal user or suffer from being way too centralized.

## TODO:
- [TODO](/docs/TODO.md)


## Documentation:

- [Compiling](/INSTALL.md)
- [DHT Protocol](/docs/updates/DHT.md)<br />
- [Crypto](/docs/updates/Crypto.md)<br />
