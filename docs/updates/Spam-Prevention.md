 
Situation 1:
Someone randomly goes around the DHT sending friend requests to everyone.

Prevented by:
Every friend address: 
[client_id (32 bytes)][nospam number (4 bytes)][checksum (2 bytes)] 
contains a number (nospam).

The nospam in every friend request to that friend must be that number.

If not it is rejected.
