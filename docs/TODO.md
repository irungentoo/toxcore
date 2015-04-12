# Toxcore todo list.
Welcome to the Toxcore todo list, this is very likely out of date, but either way it's a good jumping off point if
you're looking to see where core is going, or where it could use a little love.

There are 3 sections; In Progress, TODO, and Done. These tasks are somewhat sorted by priority, but that shouldn't be
taken to mean that this is the order tasks will (or should) be completed in.

## In Progress
 - [ ] [IN PROGRESS] Audio/Video
     - [X] [DONE] encoding/streaming/decoding
     - [X] [DONE] Call initiation
     - [X] [DONE] Encryption
     - [ ] [NEEDS TESTING] Video packet splitting.
     - [ ] [IN PROGRESS] Auditing.
     - [ ] [IN PROGRESS] Prevent audio skew (seems to be easily solvable client side.)
     - [ ] [IN PROGRESS] Group chats, audio done.
 - [ ] Networking:
     - [ ] [NEEDS TESTING] UPnP port forwarding. ([#969](https://github.com/irungentoo/toxcore/pull/969))
     - [ ] [TODO] NAT-PMP port forwarding.
 - [ ] DHT:
     - [ ] [ALMOST DONE] Metadata collection prevention. (docs/Prevent_Tracking.txt)
     - [ ] [IN PROGRESS] Hardening against attacks.
     - [ ] [IN PROGRESS] Optimizing the code.
 - [ ] [DONE] Friend only group chats
     - [X] [DONE] Networking base.
     - [X] [MOSTLY DONE] Syncing chat state between clients (nicknames, list of who is in chat, etc...)
     - [ ] [TODO] Group private messages. (and adding friends from group chats using those private messages.)
     - [ ] [TODO] Group file transfers.
 - [ ] [IN PROGRESS] Friends list syncing
 - [ ] [IN PROGRESS] Make toxcore thread safe.
 - [ ] [MOSTLY DONE] A way for people to connect to people on Tox if they are behind a bad NAT that blocks UDP (or is
just unpunchable) ([docs/TCP_Network.txt](TCP_Network.txt)) (Current way doesn't scale very well.)

## TODO
 - [ ] [TODO] Make the core save/datafile portable across client versions/different processor architectures.
 - [ ] [TODO] Friend_requests.c:
     - [ ] [TODO] What happens when a friend request is received needs to be changed.
     - [ ] [DONE?] Add multiple nospam functionality. ([#1317](https://github.com/irungentoo/toxcore/pull/1317))

 - [ ] [TODO] Offline messaging
 - [ ] [TODO] Security audit from professionals

## Done
 - [X] [DONE] File transfers
 - [X] [DONE] IPV6 support
 - [X] [DONE] Encrypted Saves. (see: toxencryptsave)
