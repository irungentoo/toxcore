Group chats.

Note: we assume everyone in the chat trusts each other.

These group chats work by temporarily adding the 4 "closest" people defined by a distance function 
in group.c in order to form a circle of connected peers. These peers then relay messages to each other.

A friend invites another friend to a group chat by sending them an invite packet. The friend either ignores 
the invite or responds with a response packet if he wants to join the chat. The friend invite contains the type
of groupchat (text only, A/V) the friend is being invited to.


TODO(irungentoo): write more of this.

## Protocol

Invite packets:
Invite packet:
[uint8_t id 96][uint8_t id 0][uint16_t group chat number][33 bytes group chat identifier[1 byte type][32 bytes id]]

Response packet
[uint8_t id 96][uint8_t id 1][uint16_t group chat number(local)][uint16_t group chat number to join][33 bytes group chat identifier[1 byte type][32 bytes id]]


Peer online packet:
[uint8_t id 97][uint16_t group chat number (local)][33 bytes group chat identifier[1 byte type][32 bytes id]]

Peer leave packet:
[uint8_t id 98][uint16_t group chat number][uint8_t id 1]

Peer query packet:
[uint8_t id 98][uint16_t group chat number][uint8_t id 8]

Peer response packet:
[uint8_t id 98][uint16_t group chat number][uint8_t id 9][Repeated times number of peers: [uint16_t peer num][uint8_t 32bytes real public key][uint8_t 32bytes temp DHT public key][uint8_t name length][name]] 

Title response packet:
[uint8_t id 98][uint16_t group chat number][uint8_t id 10][title]

Message packets:
[uint8_t id 99][uint16_t group chat number][uint16_t peer number][uint32_t message number][uint8_t with a value representing id of message][data]

Lossy Message packets:
[uint8_t id 199][uint16_t group chat number][uint16_t peer number][uint16_t message number][uint8_t with a value representing id of message][data]

Group chat types:
0: text
1: AV


Note: the message number is increased by 1 for each sent message.

message ids:
0 - ping
sent every ~60 seconds by every peer.
No data.

16 - new_peer
Tell everyone about a new peer in the chat.
[uint16_t peer_num][uint8_t 32bytes real public key][uint8_t 32bytes temp DHT public key]

17 - kill_peer
[uint16_t peer_num]

48 - name change
[uint8_t name[namelen]]

49 - groupchat title change
[uint8_t title[titlelen]]

64 - chat message
[uint8_t message[messagelen]]

65 - action (/me)
[uint8_t message[messagelen]]



