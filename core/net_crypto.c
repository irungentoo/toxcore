/* net_crypto.c
* 
* Functions for the core network crypto.
* See also: docs/Crypto.txt
* 
* NOTE: This code has to be perfect. We don't mess around with encryption.
*
 
    Copyright (C) 2013 Tox project All Rights Reserved.

    This file is part of Tox.

    Tox is free software: you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation, either version 3 of the License, or
    (at your option) any later version.

    Tox is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with Tox.  If not, see <http://www.gnu.org/licenses/>.
    
*/

#include "net_crypto.h"


//Our public and secret keys.
uint8_t self_public_key[crypto_box_PUBLICKEYBYTES];
uint8_t self_secret_key[crypto_box_SECRETKEYBYTES];


typedef struct
{
    uint8_t public_key[crypto_box_PUBLICKEYBYTES];//the real public key of the peer.
    uint8_t recv_nonce[crypto_box_NONCEBYTES];//nonce of received packets
    uint8_t sent_nonce[crypto_box_NONCEBYTES];//nonce of sent packets.
    uint8_t sessionpublic_key[crypto_box_PUBLICKEYBYTES];//our public key for this session.
    uint8_t sessionsecret_key[crypto_box_SECRETKEYBYTES];//our private key for this session.
    uint8_t peersessionpublic_key[crypto_box_PUBLICKEYBYTES];//The public key of the peer.
    uint8_t status;//0 if no connection, 1 we have sent a handshake, 2 if connexion is not confirmed yet 
                   //(we have received a handshake but no empty data packet), 3 if the connection is established.
                   //4 if the connection is timed out.
    uint16_t number; //Lossless_UDP connection number corresponding to this connection.
    
}Crypto_Connection;

#define MAX_CRYPTO_CONNECTIONS 256

static Crypto_Connection crypto_connections[MAX_CRYPTO_CONNECTIONS];

#define MAX_FRIEND_REQUESTS 32

//keeps track of the connection numbers for friends request so we can check later if they were sent
static int outbound_friendrequests[MAX_FRIEND_REQUESTS];

#define MAX_INCOMING 64

//keeps track of the connection numbers for friends request so we can check later if they were sent
static int incoming_connections[MAX_INCOMING];

//encrypts plain of length length to encrypted of length + 16 using the 
//public key(32 bytes) of the receiver and the secret key of the sender and a 24 byte nonce
//return -1 if there was a problem.
//return length of encrypted data if everything was fine.
int encrypt_data(uint8_t * public_key, uint8_t * secret_key, uint8_t * nonce, 
                                       uint8_t * plain, uint32_t length, uint8_t * encrypted)
{
    if(length - crypto_box_BOXZEROBYTES + crypto_box_ZEROBYTES > MAX_DATA_SIZE || length == 0)
    {
        return -1;
    }
    
    uint8_t temp_plain[MAX_DATA_SIZE + crypto_box_ZEROBYTES - crypto_box_BOXZEROBYTES] = {0};
    uint8_t temp_encrypted[MAX_DATA_SIZE + crypto_box_ZEROBYTES];
    uint8_t zeroes[crypto_box_BOXZEROBYTES] = {0};
    
    memcpy(temp_plain + crypto_box_ZEROBYTES, plain, length);//pad the message with 32 0 bytes.
    
    crypto_box(temp_encrypted, temp_plain, length + crypto_box_ZEROBYTES, nonce, public_key, secret_key);
    
    //if encryption is successful the first crypto_box_BOXZEROBYTES of the message will be zero
    if(memcmp(temp_encrypted, zeroes, crypto_box_BOXZEROBYTES) != 0)
    {
        return -1;
    }
    //unpad the encrypted message
    memcpy(encrypted, temp_encrypted + crypto_box_BOXZEROBYTES, length - crypto_box_BOXZEROBYTES + crypto_box_ZEROBYTES);
    return length - crypto_box_BOXZEROBYTES + crypto_box_ZEROBYTES;
}

//decrypts encrypted of length length to plain of length length - 16 using the
//public key(32 bytes) of the sender, the secret key of the receiver and a 24 byte nonce
//return -1 if there was a problem(decryption failed)
//return length of plain data if everything was fine.
int decrypt_data(uint8_t * public_key, uint8_t * secret_key, uint8_t * nonce, 
                                       uint8_t * encrypted, uint32_t length, uint8_t * plain)
{
    if(length > MAX_DATA_SIZE || length <= crypto_box_BOXZEROBYTES)
    {
        return -1;
    }
    uint8_t temp_plain[MAX_DATA_SIZE - crypto_box_ZEROBYTES + crypto_box_BOXZEROBYTES];
    uint8_t temp_encrypted[MAX_DATA_SIZE + crypto_box_ZEROBYTES] = {0};
    uint8_t zeroes[crypto_box_ZEROBYTES] = {0};
    
    memcpy(temp_encrypted + crypto_box_BOXZEROBYTES, encrypted, length);//pad the message with 16 0 bytes.
    
    if(crypto_box_open(temp_plain, temp_encrypted, length + crypto_box_BOXZEROBYTES, 
                                            nonce, public_key, secret_key) == -1)
    {
        return -1;
    }
    //if decryption is successful the first crypto_box_ZEROBYTES of the message will be zero
    if(memcmp(temp_plain, zeroes, crypto_box_ZEROBYTES) != 0)
    {
        return -1;
    }
    //unpad the plain message
    memcpy(plain, temp_plain + crypto_box_ZEROBYTES, length - crypto_box_ZEROBYTES + crypto_box_BOXZEROBYTES);
    return length - crypto_box_ZEROBYTES + crypto_box_BOXZEROBYTES;
}

//increment the given nonce by 1
void increment_nonce(uint8_t * nonce)
{
    uint32_t i;
    for(i = 0; i < crypto_box_NONCEBYTES; i++)
    {
        nonce[i]++;
        if(nonce[i] != 0)
        {
            break;
        }
    }
}

//fill the given nonce with random bytes.
//TODO: make this more optimized
void random_nonce(uint8_t * nonce)
{
    uint32_t i;
    for(i = 0; i < crypto_box_NONCEBYTES; i++)
    {
        nonce[i] = random_int() % 256;
    }
}

//return 0 if there is no received data in the buffer 
//return -1  if the packet was discarded.
//return length of received data if successful
int read_cryptpacket(int crypt_connection_id, uint8_t * data)
{
    if(crypt_connection_id < 0 || crypt_connection_id >= MAX_CRYPTO_CONNECTIONS)
    {
        return 0;   
    }
    if(crypto_connections[crypt_connection_id].status != 3)
    {
        return 0;
    }
    uint8_t temp_data[MAX_DATA_SIZE];
    int length = read_packet(crypto_connections[crypt_connection_id].number, temp_data);
    if(length == 0)
    {
        return 0;
    }
    if(temp_data[0] != 3)
    {
        return -1;
    }
    int len = decrypt_data(crypto_connections[crypt_connection_id].peersessionpublic_key, 
                           crypto_connections[crypt_connection_id].sessionsecret_key,
                           crypto_connections[crypt_connection_id].recv_nonce, temp_data + 1, length - 1, data);
    if(len != -1)
    {
        increment_nonce(crypto_connections[crypt_connection_id].recv_nonce);
        return len;
    }
    return -1;
}


//return 0 if data could not be put in packet queue
//return 1 if data was put into the queue
int write_cryptpacket(int crypt_connection_id, uint8_t * data, uint32_t length)
{
    if(crypt_connection_id < 0 || crypt_connection_id >= MAX_CRYPTO_CONNECTIONS)
    {
        return 0;   
    }
    if(length - crypto_box_BOXZEROBYTES + crypto_box_ZEROBYTES > MAX_DATA_SIZE - 1)
    {
        return 0;
    }
    if(crypto_connections[crypt_connection_id].status != 3)
    {
        return 0;
    }
    uint8_t temp_data[MAX_DATA_SIZE];
    int len = encrypt_data(crypto_connections[crypt_connection_id].peersessionpublic_key, 
                           crypto_connections[crypt_connection_id].sessionsecret_key,
                           crypto_connections[crypt_connection_id].sent_nonce, data, length, temp_data + 1);
    if(len == -1)
    {
        return 0;
    }
    temp_data[0] = 3;
    if(write_packet(crypto_connections[crypt_connection_id].number, temp_data, len + 1) == 0)
    {
        return 0;
    }
    increment_nonce(crypto_connections[crypt_connection_id].sent_nonce);
    return 1;
}

//send a friend request to peer with public_key and ip_port.
//Data represents the data we send with the friends request.
//returns -1 on failure
//returns a positive friend request id that can be used later to see if it was sent correctly on success.
int send_friendrequest(uint8_t * public_key, IP_Port ip_port, uint8_t * data, uint32_t length)
{
    if(length > MAX_DATA_SIZE - 1 - crypto_box_PUBLICKEYBYTES - crypto_box_NONCEBYTES)
    {
        return -1;
    }
    uint32_t i;
    for(i = 0; i < MAX_FRIEND_REQUESTS; i++)
    {
        if(outbound_friendrequests[i] == -1)
        {
            break;
        }
    }
    if(i == MAX_FRIEND_REQUESTS)
    {
        return -1;
    }
    uint8_t temp_data[MAX_DATA_SIZE];
    uint8_t nonce[crypto_box_NONCEBYTES];
    random_nonce(nonce);
    int len = encrypt_data(public_key, self_secret_key, nonce, data, length, 
                           1 + crypto_box_PUBLICKEYBYTES + crypto_box_NONCEBYTES + temp_data);
    if(len == -1)
    {
        return -1;
    }
    temp_data[0] = 1;
    memcpy(temp_data + 1, self_public_key, crypto_box_PUBLICKEYBYTES);
    memcpy(temp_data + 1 + crypto_box_PUBLICKEYBYTES, nonce, crypto_box_NONCEBYTES);
    int id = new_connection(ip_port);
    if(id == -1)
    {
        return -1;
    }
    if(write_packet(id, temp_data, len + 1 + crypto_box_PUBLICKEYBYTES + crypto_box_NONCEBYTES) == 1)
    {
        outbound_friendrequests[i] = id;
        return i;
    }
    return -1;
}

//return -1 if failure
//return 0 if connection is still trying to send the request.
//return 1 if sent correctly
//return 2 if connection timed out
int check_friendrequest(int friend_request)
{
    if(friend_request < 0 || friend_request > MAX_FRIEND_REQUESTS)
    {
        return -1;
    }
    if(outbound_friendrequests[friend_request] == -1)
    {
        return -1;
    }
    if(sendqueue(outbound_friendrequests[friend_request]) == 0)
    {
        kill_connection(outbound_friendrequests[friend_request]);
        outbound_friendrequests[friend_request] = -1;
        return 1;
    }
    int status = is_connected(outbound_friendrequests[friend_request]);
    if(status == 4)
    {
        kill_connection(outbound_friendrequests[friend_request]);
        outbound_friendrequests[friend_request] = -1;
        return 2;
    }
    if(status == 0)
    {
        outbound_friendrequests[friend_request] = -1;
        return 2;
    }
    return 0;
}

//Send a crypto handshake packet containing an encrypted secret nonce and session public key
//to peer with connection_id and public_key
//the packet is encrypted with a random nonce which is sent in plain text with the packet
int send_cryptohandshake(int connection_id, uint8_t * public_key, uint8_t * secret_nonce, uint8_t * session_key)
{
    uint8_t temp_data[MAX_DATA_SIZE];
    uint8_t temp[crypto_box_NONCEBYTES + crypto_box_PUBLICKEYBYTES];
    uint8_t nonce[crypto_box_NONCEBYTES];
    
    random_nonce(nonce);
    memcpy(temp, secret_nonce, crypto_box_NONCEBYTES);
    memcpy(temp + crypto_box_NONCEBYTES, session_key, crypto_box_PUBLICKEYBYTES);
    
    int len = encrypt_data(public_key, self_secret_key, nonce, temp, crypto_box_NONCEBYTES + crypto_box_PUBLICKEYBYTES, 
                             1 + crypto_box_PUBLICKEYBYTES + crypto_box_NONCEBYTES + temp_data);
    if(len == -1)
    {
        return 0;
    }
    temp_data[0] = 2;
    memcpy(temp_data + 1, self_public_key, crypto_box_PUBLICKEYBYTES);
    memcpy(temp_data + 1 + crypto_box_PUBLICKEYBYTES, nonce, crypto_box_NONCEBYTES);
    return write_packet(connection_id, temp_data, len + 1 + crypto_box_PUBLICKEYBYTES + crypto_box_NONCEBYTES);
}

//Extract secret nonce, session public key and public_key from a packet(data) with length length
//return 1 if successful
//return 0 if failure
int handle_cryptohandshake(uint8_t * public_key, uint8_t * secret_nonce, 
                           uint8_t * session_key, uint8_t * data, uint16_t length)
{
    int pad = (- crypto_box_BOXZEROBYTES + crypto_box_ZEROBYTES);
    if(length != 1 + crypto_box_PUBLICKEYBYTES + crypto_box_NONCEBYTES 
                              + crypto_box_NONCEBYTES + crypto_box_PUBLICKEYBYTES + pad)
    {
        return 0;
    }
    if(data[0] != 2)
    {
        return 0;
    }
    uint8_t temp[crypto_box_NONCEBYTES + crypto_box_PUBLICKEYBYTES];
    
    memcpy(public_key, data + 1, crypto_box_PUBLICKEYBYTES);
    
    int len = decrypt_data(public_key, self_secret_key, data + 1 + crypto_box_PUBLICKEYBYTES, 
              data + 1 + crypto_box_PUBLICKEYBYTES + crypto_box_NONCEBYTES, 
              crypto_box_NONCEBYTES + crypto_box_PUBLICKEYBYTES + pad, temp);
    
    if(len != crypto_box_NONCEBYTES + crypto_box_PUBLICKEYBYTES)
    {
        return 0;
    }
    
    memcpy(secret_nonce, temp, crypto_box_NONCEBYTES);
    memcpy(session_key, temp + crypto_box_NONCEBYTES, crypto_box_PUBLICKEYBYTES);
    return 1;
}


//puts the public key of the friend if public_key, the  data from the request 
//in data if a friend request was sent to us and returns the length of the data.
//return -1 if no valid friend requests.
int handle_friendrequest(uint8_t * public_key, uint8_t * data)
{
    uint32_t i;
    for(i = 0; i < MAX_INCOMING; i++)
    {
        if(incoming_connections[i] != -1)
        {
            if(id_packet(incoming_connections[i]) == 1)
            {
                uint8_t temp_data[MAX_DATA_SIZE];
                uint16_t len = read_packet(incoming_connections[i], temp_data);
                if(len > crypto_box_PUBLICKEYBYTES + crypto_box_NONCEBYTES + 1 
                                 - crypto_box_BOXZEROBYTES + crypto_box_ZEROBYTES)
                {
                    memcpy(public_key, temp_data + 1, crypto_box_PUBLICKEYBYTES);
                    uint8_t nonce[crypto_box_NONCEBYTES];
                    memcpy(nonce, temp_data + 1 + crypto_box_PUBLICKEYBYTES, crypto_box_NONCEBYTES);
                    int len1 = decrypt_data(public_key, self_secret_key, nonce, temp_data + 1 + crypto_box_PUBLICKEYBYTES + crypto_box_NONCEBYTES, 
                                                    len - (crypto_box_PUBLICKEYBYTES + crypto_box_NONCEBYTES + 1), data);
                    if(len1 != -1)
                    {
                        kill_connection(incoming_connections[i]);
                        //kill_connection_in(incoming_connections[i], 1); //conection is useless now, kill it in 1 seconds
                        incoming_connections[i] = -1;
                        return len1;
                    }
                }
                kill_connection(incoming_connections[i]); //conection is useless now, kill it.
                incoming_connections[i] = -1;
            }
        }
    }
    return -1;
}

//get crypto connection id from public key of peer
//return -1 if there are no connections like we are looking for
//return id if it found it
int getcryptconnection_id(uint8_t * public_key)
{
    uint32_t i;
    for(i = 0; i < MAX_CRYPTO_CONNECTIONS; i++)
    {
        if(crypto_connections[i].status > 0)
        {
            if(memcmp(public_key, crypto_connections[i].public_key, crypto_box_PUBLICKEYBYTES) == 0)
            {
                return i;
            }
        }
    }
    return -1;
}


//Start a secure connection with other peer who has public_key and ip_port
//returns -1 if failure
//returns crypt_connection_id of the initialized connection if everything went well.
int crypto_connect(uint8_t * public_key, IP_Port ip_port)
{
    uint32_t i;
    if(getcryptconnection_id(public_key) != -1)
    {
        return -1;
    }
    for(i = 0; i < MAX_CRYPTO_CONNECTIONS; i++)
    {
        if(crypto_connections[i].status == 0)
        {
            int id = new_connection(ip_port);
            if(id == -1)
            {
                return -1;
            }
            crypto_connections[i].number = id;
            crypto_connections[i].status = 1;
            random_nonce(crypto_connections[i].recv_nonce);
            memcpy(crypto_connections[i].public_key, public_key, crypto_box_PUBLICKEYBYTES);
            crypto_box_keypair(crypto_connections[i].sessionpublic_key, crypto_connections[i].sessionsecret_key);

            if(send_cryptohandshake(id, public_key, crypto_connections[i].recv_nonce, 
                                                               crypto_connections[i].sessionpublic_key) == 1)
            {
                increment_nonce(crypto_connections[i].recv_nonce);
                return i;
            }
            return -1;//this should never happen.
        }
    }
    return -1;
}

//handle an incoming connection
//return -1 if no crypto inbound connection
//return incoming connection id (Lossless_UDP one) if there is an incoming crypto connection
//Put the public key of the peer in public_key, the secret_nonce from the handshake into secret_nonce
//and the session public key for the connection in session_key
//to accept it see: accept_crypto_inbound(...)
//to refuse it just call kill_connection(...) on the connection id
int crypto_inbound(uint8_t * public_key, uint8_t * secret_nonce, uint8_t * session_key)
{
    uint32_t i;
    for(i = 0; i < MAX_INCOMING; i++)
    {
        if(incoming_connections[i] != -1)
        {
            if(id_packet(incoming_connections[i]) == 2)
            {
                uint8_t temp_data[MAX_DATA_SIZE];
                uint16_t len = read_packet(incoming_connections[i], temp_data);
                if(handle_cryptohandshake(public_key, secret_nonce, session_key, temp_data, len))
                {
                    int connection_id = incoming_connections[i];
                    incoming_connections[i] = -1;//remove this connection from the incoming connection list.
                    return connection_id;
                }
            }
        }
    }
    return -1;
}

//kill a crypto connection
//return 0 if killed successfully
//return 1 if there was a problem.
int crypto_kill(int crypt_connection_id)
{ 
    if(crypt_connection_id < 0 || crypt_connection_id >= MAX_CRYPTO_CONNECTIONS)
    {
        return 1;   
    }
    if(crypto_connections[crypt_connection_id].status != 0)
    {
        crypto_connections[crypt_connection_id].status = 0;
        kill_connection(crypto_connections[crypt_connection_id].number);
        return 0;
    }
    return 1;
}


//accept an incoming connection using the parameters provided by crypto_inbound
//return -1 if not successful
//returns the crypt_connection_id if successful
int accept_crypto_inbound(int connection_id, uint8_t * public_key, uint8_t * secret_nonce, uint8_t * session_key)
{
    uint32_t i;
    if(connection_id == -1)
    {
        return -1;
    }
    if(getcryptconnection_id(public_key) != -1)
    {
        return -1;
    }
    for(i = 0; i < MAX_CRYPTO_CONNECTIONS; i++)
    {
        if(crypto_connections[i].status == 0)
        {
            crypto_connections[i].number = connection_id;
            crypto_connections[i].status = 2;
            random_nonce(crypto_connections[i].recv_nonce);
            memcpy(crypto_connections[i].sent_nonce, secret_nonce, crypto_box_NONCEBYTES);
            memcpy(crypto_connections[i].peersessionpublic_key, session_key, crypto_box_PUBLICKEYBYTES);
            increment_nonce(crypto_connections[i].sent_nonce);
            memcpy(crypto_connections[i].public_key, public_key, crypto_box_PUBLICKEYBYTES);

            crypto_box_keypair(crypto_connections[i].sessionpublic_key, crypto_connections[i].sessionsecret_key);

            if(send_cryptohandshake(connection_id, public_key, crypto_connections[i].recv_nonce, 
                                                               crypto_connections[i].sessionpublic_key) == 1)
            {
                increment_nonce(crypto_connections[i].recv_nonce);
                uint32_t zero = 0;
                crypto_connections[i].status = 3;//connection status needs to be 3 for write_cryptpacket() to work
                write_cryptpacket(i, ((uint8_t *)&zero), sizeof(zero));
                crypto_connections[i].status = 2;//set it to its proper value right after.
                return i;
            }
            return -1;//this should never happen.
        }
    }
    return -1;    
}

//return 0 if no connection, 1 we have sent a handshake, 2 if connexion is not confirmed yet 
//(we have received a handshake but no empty data packet), 3 if the connection is established.
//4 if the connection is timed out and waiting to be killed
int is_cryptoconnected(int crypt_connection_id)
{
    if(crypt_connection_id >= 0 && crypt_connection_id < MAX_CRYPTO_CONNECTIONS)
    {
        return crypto_connections[crypt_connection_id].status;
    }
    return 0;
}


//Generate our public and private keys
//Only call this function the first time the program starts.
void new_keys()
{
    crypto_box_keypair(self_public_key,self_secret_key);
}

//TODO: optimize this
//adds an incoming connection to the incoming_connection list.
//returns 0 if successful
//returns 1 if failure
int new_incoming(int id)
{
    uint32_t i;
    for(i = 0; i < MAX_INCOMING; i++)
    {
        if(incoming_connections[i] == -1)
        {
            incoming_connections[i] = id;
            return 0;
        }
    }
    return 1;
}

//TODO: optimize this
//handle all new incoming connections.
static void handle_incomings()
{
    int income;
    while(1)
    {
         income = incoming_connection();
         if(income == -1 || new_incoming(income) )
         {
             break;
         }
    }
}

//handle received packets for not yet established crypto connections.
static void receive_crypto()
{
    uint32_t i;
    for(i = 0; i < MAX_CRYPTO_CONNECTIONS; i++)
    {
        if(crypto_connections[i].status == 1)
        {
            uint8_t temp_data[MAX_DATA_SIZE];
            uint8_t secret_nonce[crypto_box_NONCEBYTES];
            uint8_t public_key[crypto_box_PUBLICKEYBYTES];
            uint8_t session_key[crypto_box_PUBLICKEYBYTES];
            uint16_t len;
            if(id_packet(crypto_connections[i].number) == 1) 
            //if the packet is a friend request drop it (because we are already friends)
            {
                len = read_packet(crypto_connections[i].number, temp_data);
                
            }
            if(id_packet(crypto_connections[i].number) == 2)//handle handshake packet.
            {

                len = read_packet(crypto_connections[i].number, temp_data);
                if(handle_cryptohandshake(public_key, secret_nonce, session_key, temp_data, len))
                {
                    if(memcmp(public_key, crypto_connections[i].public_key, crypto_box_PUBLICKEYBYTES) == 0)
                    {
                        memcpy(crypto_connections[i].sent_nonce, secret_nonce, crypto_box_NONCEBYTES);
                        memcpy(crypto_connections[i].peersessionpublic_key, session_key, crypto_box_PUBLICKEYBYTES);
                        increment_nonce(crypto_connections[i].sent_nonce);
                        uint32_t zero = 0;
                        crypto_connections[i].status = 3;//connection status needs to be 3 for write_cryptpacket() to work
                        write_cryptpacket(i, ((uint8_t *)&zero), sizeof(zero));
                        crypto_connections[i].status = 2;//set it to its proper value right after.
                    }
                }
            }
            else if(id_packet(crypto_connections[i].number) != -1)
            {
                //This should not happen
                //kill the connection if it does
                crypto_kill(crypto_connections[i].number);
            }
            
        }
        if(crypto_connections[i].status == 2)
        {
            if(id_packet(crypto_connections[i].number) == 3)
            {
                uint8_t temp_data[MAX_DATA_SIZE];
                uint8_t data[MAX_DATA_SIZE];
                int length = read_packet(crypto_connections[i].number, temp_data);
                int len = decrypt_data(crypto_connections[i].peersessionpublic_key, 
                                       crypto_connections[i].sessionsecret_key,
                                       crypto_connections[i].recv_nonce, temp_data + 1, length - 1, data);
                uint32_t zero = 0;
                if(len == sizeof(uint32_t) && memcmp(((uint8_t *)&zero), data, sizeof(uint32_t)) == 0)
                {
                    increment_nonce(crypto_connections[i].recv_nonce);
                    crypto_connections[i].status = 3;
                    
                    //connection is accepted so we disable the auto kill by setting it to about 1 month from now.
                    kill_connection_in(crypto_connections[i].number, 3000000);
                }
                else
                {
                    //This should not happen
                    //kill the connection if it does
                    crypto_kill(crypto_connections[i].number);
                }
            }
            else if(id_packet(crypto_connections[i].number) != -1)
            {
                //This should not happen
                //kill the connection if it does
                crypto_kill(crypto_connections[i].number);
            }
        }
    }
}

//run this to (re)initialize net_crypto
//sets all the global connection variables to their default values.
void initNetCrypto()
{
    memset(crypto_connections, 0 ,sizeof(crypto_connections));
    memset(outbound_friendrequests, -1 ,sizeof(outbound_friendrequests));
    memset(incoming_connections, -1 ,sizeof(incoming_connections));
}

static void killTimedout()
{
    uint32_t i;
    for(i = 0; i < MAX_CRYPTO_CONNECTIONS; i++)
    {
        if(crypto_connections[i].status != 0 && is_connected(crypto_connections[i].number) == 4)
        {
            crypto_connections[i].status = 4;
        }
    }
}

//main loop
void doNetCrypto()
{
    //TODO:check if friend requests were sent correctly
    //handle new incoming connections
    //handle friend requests
    handle_incomings();
    receive_crypto();
    killTimedout();
}
