Massive public group chats.

Note that not all this document has been implemented: only private (invite only) group chats are currently implemented.

Everyone generates a short term public private key pair right before joining 
the chat.

Note that for public group chats it is impossible to protect the chat from 
being spied on by a very dedicated attacker, encryption is therefor used as a 
form of spam/access control.

## Joining the chats


## Protocol


Node format: 
See DHT, currently uses the IPv6 Node_format.

Get nodes (Request):
Packet contents: 
```
[char with a value of 48][Bob's (The receiver's) Public key (client_id) (32 bytes))][Alice's (The sender's) Public key (client_id) (32 bytes)][Random nonce (24 bytes)][Encrypted with the nonce, private key of the sender and public key of the receiver:[char with a value of 48][random 8 byte (ping_id)]
```
Valid replies: a send_nodes packet

Send_nodes (response): 
```
[char with a value of 48][Bob's (The receiver's) Public key (client_id) (32 bytes))][Alice's (The sender's) Public key (client_id) (32 bytes)][Random nonce (24 bytes)][Encrypted with the nonce, private key of the sender and public key of the receiver:[char with a value of 49][random 8 byte (ping_id)][Nodes in node format, length=40 * (number of nodes (maximum of 6 nodes)) bytes]]
```

Broadcast packet:
```
[char with a value of 48][Bob's (The receiver's) Public key (client_id) (32 bytes))][Alice's (The sender's) Public key (client_id) (32 bytes)][nonce][Encrypted with the nonce, private key of the sender and public key of the receiver:[char with a value of 50][Data to send to everyone]]
```


Data to send to everyone:
TODO: signing and spam control + permissions.
[client_id of sender][uint32_t message number][char with a value representing id of message][data]

Note: the message number is increased by 1 for each sent message.

message ids:
0 - ping
sent every ~60 seconds by every peer.
No data.

16 - new_peer
Tell everyone about a new peer in the chat.
[uint8_t public_key[public_key_len]]

17 - ban_peer
Ban a peer
[uint8_t public_key[public_key_len]]

18 - topic change
[uint8_t topic[topiclen]]

48 - name change
[uint8_t name[namelen]]

49 - status change
[uint8_t (status id)]

64 - chat message
[uint8_t message[messagelen]]

65 - action (/me)
[uint8_t message[messagelen]]
