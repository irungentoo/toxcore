![Project Tox](https://raw.github.com/TokTok/toxcore/master/other/tox.png "Project Tox")
***

**Current build status:** [![Build Status](https://travis-ci.org/TokTok/c-toxcore.svg?branch=master)](https://travis-ci.org/TokTok/c-toxcore)
**Current Coverage:** [![Coverage Status](https://coveralls.io/repos/github/TokTok/toxcore/badge.svg?branch=master)](https://coveralls.io/github/TokTok/toxcore?branch=master)

[**Website**](https://tox.chat) **|** [**Wiki**](https://wiki.tox.chat/) **|** [**Blog**](https://blog.tox.chat/) **|** [**FAQ**](https://wiki.tox.chat/doku.php?id=users:faq) **|** [**Binaries/Downloads**](https://wiki.tox.chat/Binaries) **|** [**Clients**](https://wiki.tox.chat/doku.php?id=clients) **|** [**Compiling**](/INSTALL.md)

**IRC Channels:** Users: [#tox@freenode](https://webchat.freenode.net/?channels=tox), Developers: [#toktok@freenode](https://webchat.freenode.net/?channels=toktok)

## Toxcore Development Roadmap
This Roadmap is somewhat tentative, but should give you a good idea of where
we're going, and where we've been.

Currently unsorted, the following is intended to function as a discussion guide
to developers/contributors.

### In Progress
- [ ] Toxcore
    - [ ] 100% unit testing
    - [ ] Make ToxAV stateless
    - [ ] Allow a single toxcore instance to handle multiple keypairs (or 'clients')
    - [ ] Consistent naming scheme throughout toxcore
    - [X] Make toxcore stateless
- [ ] Messenger
    - [ ] Improve group chat implementation
    - [ ] Improve A/V implementation
    - [ ] Multiple device support

### Done
- [X] Create Toxcore
- [X] Create DHT
- [X] Create Onion
- [X] Implement Crypto
- [X] Create Messenger

## Q&A:

### What is Tox?

Tox is a fully encrypted, censor resistant, private, distributed network library with a focus on personal communications.

### No, really, what's Tox?

It's a VERY secure Instant Messenger that supports Text, Audio/Video calls, group chats, audio group chats, and file transfers. There's dozens, but our advantage is we put security first, from day 1. We didn't decide to add it in after.

### What are your goals with Tox?

We want Tox to be as simple as possible while remaining as secure as possible.

## Documentation:
- [Compiling](/INSTALL.md)
- [DHT Protocol](/docs/updates/DHT.md)<br />
- [Crypto](/docs/updates/Crypto.md)<br />

## The Complex Stuff:
### UDP vs. TCP
Tox must use UDP simply because [hole punching](https://en.wikipedia.org/wiki/UDP_hole_punching) with TCP is not as reliable.
However, Tox does use [TCP relays](/docs/TCP_Network.txt) as a fallback if it encounters a firewall that prevents UDP hole punching.

### Connecting & Communicating
Every peer is represented as a [byte string](https://en.wikipedia.org/wiki/String_(computer_science)) (the public key [Tox ID] of the peer). By using torrent-style DHT, peers can find the IP of other peers by using their Tox ID. Once the IP is obtained, peers can initiate a [secure](/docs/updates/Crypto.md) connection with each other. Once the connection is made, peers can exchange messages, send files, start video chats, etc. using encrypted communications.

