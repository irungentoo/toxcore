![Project Tox](https://raw.github.com/irungentoo/ProjectTox-Core/master/other/tox.png "Project Tox")
Project Tox, _also known as Tox_, is a FOSS (Free and Open Source Software) instant messaging application aimed to replace Skype.<br />

With the rise of governmental monitoring programs, Tox aims to be an easy to use, all-in-one communication platform (including audio, and videochats in the future) that ensures their users full privacy and secure message delivery.<br /> <br />



**IRC**: #tox on freenode, alternatively, you can use the [webchat](https://webchat.freenode.net/?channels=#tox).<br />
**Website**: [https://tox.im](https://tox.im)<br>
**Jenkins**: [http://jenkins.tox.im](http://jenkins.tox.im)<br>
**Nightly Binary Downloads***: [http://download.tox.im](http://download.tox.im)

**Website translations**: [here](https://github.com/Tox/tox.im)<br/>
**Qt GUI**: [see nurupo's repository](https://github.com/nurupo/ProjectTox-Qt-GUI)

**How to build Tox** [INSTALL.md](INSTALL.md)

### Objectives:

Keep everything really simple.

## The Complex Stuff:
+ Tox must use UDP simply because [hole punching](http://en.wikipedia.org/wiki/UDP_hole_punching) with TCP is not as reliable.
+ Every peer is represented as a [byte string][String] (the public key of the peer [client ID]).
+ We're using torrent-style DHT so that peers can find the IP of the other peers when they have their ID.
+ Once the client has the IP of that peer, they start initiating a secure connection with each other. (See [Crypto](https://github.com/irungentoo/ProjectTox-Core/wiki/Crypto))
+ When both peers are securely connected, they can exchange messages, initiate a video chat, send files, etc, all using encrypted communications.
+ Current build status: [![Build Status](https://travis-ci.org/irungentoo/ProjectTox-Core.png?branch=master)](https://travis-ci.org/irungentoo/ProjectTox-Core)

## TODO:
- [TODO](/docs/TODO)

### Why are you doing this? There are already a bunch of free skype alternatives.
The goal of this project is to create a configuration-free P2P skype 
replacement. Configuration-free means that the user will simply have to open the program and 
without any account configuration will be capable of adding people to his 
friends list and start conversing with them. There are many so-called skype replacements and all of them are either hard to 
configure for the normal user or suffer from being way too centralized.

### Documentation:

- [Installation](/INSTALL.md)
- [DHT Protocol](http://wiki.tox.im/index.php/DHT)<br />
- [Lossless UDP Protocol](http://wiki.tox.im/index.php/Lossless_UDP)<br />
- [Crypto](http://wiki.tox.im/index.php/Crypto)<br />
- [Ideas](http://wiki.tox.im/index.php/Ideas)

[String]: https://en.wikipedia.org/wiki/String_(computer_science)
