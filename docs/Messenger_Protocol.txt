Protocol for messages, data, etc..

Streaming audio/video will not use this protocol as they can absorb some data loss.

The protocol itself will run on top of the encryption which means it should be
impossible for someone to know what type of data is being transmitted.(Well they
could just analyze how much data is being transmitted for a pretty good guess)

Because it runs on the encryption which itself runs on our Lossless UDP protocol
it can be guaranteed that no data will be lost.

Basic packet format:
[char data_id][data]

data_id represents the type of data.

All strings must be UTF-8.

EX: data_id 64 designates a chat message. so the packet would look like: @Hello WorldNULL
Where @ is the ASCII character for 64, "Hello World" is the message and NULL is the null string terminator.

Proposed data_ids and what they mean (in decimal)

ids 0 to 16 are reserved.

48 Username (Send this packet as soon as you connect to a friend or to each friend everytime you change names.
              Username is maximum 128 bytes long with the null terminator included)

49 Status change

64 Chat message
6? File transmission.

