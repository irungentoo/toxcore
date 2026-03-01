Encryption library used: https://doc.libsodium.org/


When running the program for the first time the crypto_box_keypair() function is used to
generate the users public-private key pair. (32 bytes each)

The generated public key is set as the client_id of the peer.

Adding a friend
---------------

Alice adds Bob to her friend list by adding his 32 byte public key (client_id) to her friend list.
2 cases:
case 1: Alice adds the public key of Bob, then Bob waits for Alice to attempt to connect to him.
case 2: Bob and Alice add their respective public keys to their friend lists at the same time.

case 1:
Alice sends an onion data (see: Prevent_tracking.txt) packet to Bob with the encrypted part containing the friend request like so:
```
[char with a value of 32][nospam number (4 bytes)][Message]
```

Ex message: hello Bob it's me Alice -_- add me pl0x.

For more info on the nospam see: Spam_Prevention.txt

Bob receives the request and decrypts the message using the function crypto_box_open()

If the message decrypts successfully:
If Alice is already in Bob's friend list: case 2
If Alice is not in Bob's friend list and the nospam is good: Bob is prompt to add Alice and is shown the message from her.
If Bob accepts Alice friend request he adds her public key to his friend list.

case 2:
Bob and Alice both have the others public key in their friend list, they are ready for the next step:   Connecting to an already added friend

In the next step only crypto_box() is used for encryption and only crypto_box_open() for decryption (just like in the last step.)


Connecting to an already added friend
-------------------------------------

see: Tox_middle_level_network_protocol.txt

Crypto request packets
--------------------------------------

```
[char with a value of 32][Bob (The receiver's) Public key (client_id) (32 bytes))][Alice's (The sender's) Public key (client_id) (32 bytes)][Random nonce (24 bytes)][Encrypted message]
```

The encrypted message is encrypted with crypto_box() (using Bob's public key, Alice's private key and the nonce (randomly generated 24 bytes)) and is a message from Alice in which she tells Bob who she is.

Each node can route the request to the receiver if they are connected to him. This is to bypass bad NATs.
