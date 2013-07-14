/* Messenger.c
* 
* An implementation of a simple text chat only messenger on the tox network core.
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

#include "Messenger.h"
 
 
typedef struct
{
    uint8_t client_id[CLIENT_ID_SIZE];
    int crypt_connection_id;
    int friend_request_id; //id of the friend request corresponding to the current friend request to the current friend.
    uint8_t status;//0 if no friend, 1 if added, 2 if friend request sent, 3 if confirmed friend, 4 if online.
    uint8_t info[MAX_DATA_SIZE]; //the data that is sent during the friend requests we do
    uint16_t info_size; //length of the info
    
}Friend;
 




#define MAX_NUM_FRIENDS 256

static Friend friendlist[MAX_NUM_FRIENDS];


static uint32_t numfriends;
 

//return the friend id associated to that public key.
//return -1 if no such friend
int getfriend_id(uint8_t * client_id)
{
    uint32_t i;
    for(i = 0; i < numfriends; i++)
    {
        if(friendlist[i].status > 0)
        {
            if(memcmp(client_id, friendlist[i].client_id, crypto_box_PUBLICKEYBYTES) == 0)
            {
                return i;
            }
        }
    }
    return -1;
}

//copies the public key associated to that friend id into client_id buffer.
//make sure that client_id is of size CLIENT_ID_SIZE.
//returns 0 if success
//return -1 if failure.
int getclient_id(int friend_id, uint8_t * client_id)
{
    if(friend_id >= numfriends || friend_id < 0)
    {
        return -1;
    }

    if(friendlist[friend_id].status > 0)
    {
        memcpy(client_id, friendlist[friend_id].client_id, CLIENT_ID_SIZE);
        return 0;
    }
    return -1;
}


//add a friend
//set the data that will be sent along with friend request
//client_id is the client id of the friend
//data is the data and length is the length
//returns the friend number if success
//return -1 if failure.
int m_addfriend(uint8_t * client_id, uint8_t * data, uint16_t length)
{
    if(length == 0 || length > MAX_DATA_SIZE - 1 - crypto_box_PUBLICKEYBYTES - crypto_box_NONCEBYTES 
                                                      - crypto_box_BOXZEROBYTES + crypto_box_ZEROBYTES)
    {
        return -1;
    }

    if(getfriend_id(client_id) != -1)
    {
        return -1;
    }
    uint32_t i;
    for(i = 0; i < (numfriends + 1); i++)
    {
        if(friendlist[i].status == 0)
        {
            DHT_addfriend(client_id);
            friendlist[i].status = 1;
            friendlist[i].friend_request_id = -1;
            memcpy(friendlist[i].client_id, client_id, CLIENT_ID_SIZE);
            
            memcpy(friendlist[i].info, data, length);
            friendlist[i].info_size = length;
            
            numfriends++;
            return i;
        }
    }
    return -1;
}

int m_addfriend_norequest(uint8_t * client_id)
{
    if(getfriend_id(client_id) != -1)
    {
        return -1;
    }
    uint32_t i;
    for(i = 0; i < (numfriends + 1); i++)
    {
        if(friendlist[i].status == 0)
        {
            DHT_addfriend(client_id);
            friendlist[i].status = 2;
            friendlist[i].friend_request_id = -1;
            memcpy(friendlist[i].client_id, client_id, CLIENT_ID_SIZE);
            numfriends++;
            return i;
        }
    }
    return -1;
}

//remove a friend
//returns 0 if success
//return -1 if failure.
int m_delfriend(int friendnumber)
{
    if(friendnumber >= numfriends || friendnumber < 0)
    {
        return -1;
    }

    DHT_delfriend(friendlist[friendnumber].client_id);
    memset(&friendlist[friendnumber], 0, sizeof(Friend));
    uint32_t i;
    for(i = numfriends; i != 0; i--)
    {
        if(friendlist[i].status != 0)
        {
            break;
        }
    }
    numfriends = i;
    return 0;
}


//return 4 if friend is online
//return 3 if friend is confirmed
//return 2 if the friend request was sent
//return 1 if the friend was added
//return 0 if there is no friend with that number.
int m_friendstatus(int friendnumber)
{
    if(friendnumber < 0 || friendnumber >= MAX_NUM_FRIENDS)
    {
        return 0;
    }
    return friendlist[friendnumber].status;
}


//send a text chat message to an online friend.
//returns 1 if packet was successfully put into the send queue
//return 0 if it was not.
int m_sendmessage(int friendnumber, uint8_t * message, uint32_t length)
{
    if(friendnumber < 0 || friendnumber >= MAX_NUM_FRIENDS)
    {
        return 0;
    }
    if(length >= MAX_DATA_SIZE || friendlist[friendnumber].status != 4)
    //this does not mean the maximum message length is MAX_DATA_SIZE - 1, it is actually 17 bytes less.
    {
        return 0;   
    }
    uint8_t temp[MAX_DATA_SIZE];
    temp[0] = 64;
    memcpy(temp + 1, message, length);
    return write_cryptpacket(friendlist[friendnumber].crypt_connection_id, temp, length + 1);
    
}


static void (*friend_request)(uint8_t *, uint8_t *, uint16_t);

//set the function that will be executed when a friend request is received.
void m_callback_friendrequest(void (*function)(uint8_t *, uint8_t *, uint16_t))
{
    friend_request = function;
}


static void (*friend_message)(int, uint8_t *, uint16_t);

//set the function that will be executed when a message from a friend is received.
void m_callback_friendmessage(void (*function)(int, uint8_t *, uint16_t))
{
    friend_message = function;
}


#define PORT 33445
//run this at startup
void initMessenger()
{
    new_keys();
    initNetCrypto();
    IP ip;
    ip.i = 0;
    init_networking(ip, PORT);
    
}

static void doFriends()
{//TODO: add incoming connections and some other stuff.
    uint32_t i;
    int len;
    uint8_t temp[MAX_DATA_SIZE];
    for(i = 0; i < numfriends; i++)
    {
        if(friendlist[i].status == 1)
        {
             IP_Port friendip = DHT_getfriendip(friendlist[i].client_id);
             int request = check_friendrequest(friendlist[i].friend_request_id);
             //printf("\n%u %u %u\n", friendip.ip.i, request, friendlist[i].friend_request_id);
             if(friendip.ip.i > 1 && request == -1)
             {
                  friendlist[i].friend_request_id = send_friendrequest(friendlist[i].client_id, 
                                               friendip, friendlist[i].info, friendlist[i].info_size);
                  friendlist[i].status = 2;
             }
        }
        if(friendlist[i].status == 2 || friendlist[i].status == 3)
        {
            check_friendrequest(friendlist[i].friend_request_id);//for now this is used to kill the friend request
            
            IP_Port friendip = DHT_getfriendip(friendlist[i].client_id);
            if(is_cryptoconnected(friendlist[i].crypt_connection_id) == 0 && friendip.ip.i > 1)
            {
                 friendlist[i].crypt_connection_id = crypto_connect(friendlist[i].client_id, friendip);
            }
            if(is_cryptoconnected(friendlist[i].crypt_connection_id) == 3)//if connection is established.
            {
                 friendlist[i].status = 4;
            }
            if(is_cryptoconnected(friendlist[i].crypt_connection_id) == 4)
            {
                crypto_kill(friendlist[i].crypt_connection_id);
            }
        }
        while(friendlist[i].status == 4)
        {
            len = read_cryptpacket(friendlist[i].crypt_connection_id, temp);
            if(len > 0)
            {
                 if(temp[0] == 64)
                 {
                     (*friend_message)(i, temp + 1, len - 1);
                 }
            }
            else
            {
                 if(is_cryptoconnected(friendlist[i].crypt_connection_id) == 4)//if the connection timed out, kill it
                 {
                         crypto_kill(friendlist[i].crypt_connection_id);
                         friendlist[i].status = 3;
                 }
                 break;
            }
        }
    }
}

static void doFriendRequest()
{
    uint8_t public_key[crypto_box_PUBLICKEYBYTES];
    uint8_t temp[MAX_DATA_SIZE];
    
    int len = handle_friendrequest(public_key, temp);
    if(len >= 0)
    {
        (*friend_request)(public_key, temp, len);

    }

}



static void doInbound()
{
    uint8_t secret_nonce[crypto_box_NONCEBYTES];
    uint8_t public_key[crypto_box_PUBLICKEYBYTES];
    uint8_t session_key[crypto_box_PUBLICKEYBYTES];
    int inconnection = crypto_inbound(public_key, secret_nonce, session_key);
    if(inconnection != -1)
    {
        int friend_id = getfriend_id(public_key);
        if(friend_id != -1)
        {
             friendlist[friend_id].crypt_connection_id = 
             accept_crypto_inbound(inconnection, public_key, secret_nonce, session_key);
             
             friendlist[friend_id].status = 3;
        }
    }
}

//the main loop that needs to be run at least 200 times per second.
void doMessenger()
{
    IP_Port ip_port;
    uint8_t data[MAX_UDP_PACKET_SIZE];
    uint32_t length;
    while(receivepacket(&ip_port, data, &length) != -1)
    {
        //if(rand() % 3 != 1)//simulate packet loss
        //{
        if(DHT_handlepacket(data, length, ip_port) && LosslessUDP_handlepacket(data, length, ip_port))
        {
            //if packet is discarded
            //printf("Received unhandled packet with length: %u\n", length);
        }
        else
        {
            //printf("Received handled packet with length: %u\n", length);
        }
        //}
    }
    doDHT();
    doLossless_UDP();
    doNetCrypto();
    doInbound();
    doFriendRequest();
    doFriends();
}
