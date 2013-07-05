/* net_crypto.h
* 
* Functions for the core network crypto.
*
*/

#ifndef NET_CRYPTO_H 
#define NET_CRYPTO_H  

#include "Lossless_UDP.h"

//TODO: move this to network.h
#ifndef WIN32
#include "../nacl/build/Linux/include/amd64/crypto_box.h"
#endif
//Our public key.
extern uint8_t self_public_key[crypto_box_PUBLICKEYBYTES];



//encrypts plain of length length to encrypted of length + 16 using the 
//public key(32 bytes) of the reciever and a 24 byte nonce
//return -1 if there was a problem.
//return length of encrypted data if everything was fine.
int encrypt_data(uint8_t * public_key, uint8_t * nonce, uint8_t * plain, uint32_t length, uint8_t * encrypted);


//decrypts encrypted of length length to plain of length length - 16 using the
//public key(32 bytes) of the sender and a 24 byte nonce
//return -1 if there was a problem(decryption failed)
//return length of plain data if everything was fine.
int decrypt_data(uint8_t * public_key, uint8_t * nonce, uint8_t * encrypted, uint32_t length, uint8_t * plain);


//return 0 if there is no received data in the buffer 
//return -1  if the packet was discarded.
//return length of recieved data if successful
int read_cryptpacket(int crypt_connection_id, uint8_t * data);


//return 0 if data could not be put in packet queue
//return 1 if data was put into the queue
int write_cryptpacket(int crypt_connection_id, uint8_t * data, uint32_t length);

//send a friend request to peer with public_key and ip_port.
//Data represents the data we send with the friends request.
//returns -1 on failure
//returns a positive friend request id that can be used later to see if it was sent correctly on success.
int send_friendrequest(uint8_t * public_key, IP_Port ip_port, uint8_t * data, uint32_t length);


//return -1 if failure
//return 0 if connection is still trying to send the request.
//return 1 if sent correctly
//return 2 if connection timed out
int check_friendrequest(int friend_request);


//puts the public key of the friend if public_key, the  data from the request 
//in data if a friend request was sent to us and returns the length of the data.
//return -1 if no valid friend requests.
int handle_friendrequest(uint8_t * public_key, uint8_t * data);


//Start a secure connection with other peer who has public_key and ip_port
//returns -1 if failure
//returns crypt_connection_id of the initialized connection if everything went well.
int crypto_connect(uint8_t * public_key, IP_Port ip_port);


//kill a crypto connection
//return 0 if killed successfully
//return 1 if there was a problem.
int crypto_kill(int crypt_connection_id);

//handle an incoming connection
//return -1 if no crypto inbound connection
//return incomming connection id (Lossless_UDP one) if there is an incomming crypto connection
//Put the public key of the peer in public_key and the secret_nonce from the handshake into secret_nonce
//to accept it see: accept_crypto_inbound(...)
//to refuse it just call kill_connection(...) on the connection id
int crypto_inbound(uint8_t * public_key, uint8_t * secret_nonce);


//accept an incoming connection using the parameters provided by crypto_inbound
//return -1 if not successful
//returns the crypt_connection_id if successful
int accept_crypto_inbound(int connection_id, uint8_t * public_key, uint8_t * secret_nonce);

//return 0 if no connection, 1 we have sent a handshake, 2 if connexion is not confirmed yet 
//(we have recieved a hanshake but no empty data packet), 3 if the connection is established.
//4 if the connection is timed out and wating to be killed
int is_cryptoconnected(int crypt_connection_id);


//Generate our public and private keys
//Only call this function the first time the program starts.
void new_keys();

//run this to (re)initialize net_crypto
//sets all the global connection variables to their default values.
void initNetCrypto();

//main loop
void doNetCrypto();


#endif
