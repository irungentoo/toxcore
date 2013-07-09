/* Messenger.c
* 
* An implementation of a simple text chat only messenger on the tox network core.
* 
*/

#include "Messenger.h"
 
 
typedef struct
{
    uint8_t client_id[CLIENT_ID_SIZE];
    int crypt_connection_id;
    int friend_request_id; //id of the friend request corresponding to the current friend request to the current friend.
    uint8_t status;//0 if no friend, 1 if added, 2 if friend request successfully sent, 3 if confirmed friend, 4 if online.
    
}Friend;
 

uint8_t info[MAX_DATA_SIZE]; //the data that is sent during the friend requests we do

uint16_t info_size; //length of the info

#define MAX_NUM_FRIENDS 256

Friend friendlist[MAX_NUM_FRIENDS];

#define MAX_MESSAGE_LENGTH 256

uint32_t numfriends;
 
//add a friend
//client_id is the client i of the friend
//returns the friend number if success
//return -1 if failure.
int m_addfriend(uint8_t * client_id)
{
    
    DHT_addfriend(client_id);
    friendlist[numfriends].status = 1;
    friendlist[numfriends].friend_request_id = -1;
    memcpy(friendlist[numfriends].client_id, client_id, CLIENT_ID_SIZE);
    numfriends++;
    
    return numfriends - 1;
}

//remove a friend
int m_delfriend(int friendnumber)
{/*
    TODO
    DHT_delfriend(friendlist[friendnumber].client_id);
*/
}


//return 4 if friend is online
//return 3 if friend is confirmed
//return 2 if the friend request was sent successfully
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
    if(length >= MAX_DATA_SIZE)
    //this does not mean the maximum message length is MAX_DATA_SIZE - 1, it is actually 17 bytes less.
    {
        return 0;   
    }
    uint8_t temp[MAX_DATA_SIZE];
    temp[0] = 64;
    memcpy(temp + 1, message, length);
    return write_cryptpacket(friendlist[friendnumber].crypt_connection_id, temp, length + 1);
    
}

//set the data that will be sent along with friend requests
//return -1 if failure
//return 0 if success
int m_setinfo(uint8_t * data, uint16_t length)
{
    if(length == 0 || length > MAX_DATA_SIZE - 1 - crypto_box_PUBLICKEYBYTES - crypto_box_NONCEBYTES)
    {
        return -1;
    }
    memcpy(info, data, length);
    info_size = length;
    return 0;
}

void (*friend_request)(uint8_t *, uint8_t *, uint16_t);

//set the function that will be executed when a friend request is received.
int m_callback_friendrequest(void (*function)(uint8_t *, uint8_t *, uint16_t))
{
    friend_request = function;
}


void (*friend_message)(int, uint8_t *, uint16_t);

//set the function that will be executed when a message from a friend is received.
int m_callback_friendmessage(void (*function)(int, uint8_t *, uint16_t))
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
    memcpy(self_client_id, self_public_key, crypto_box_PUBLICKEYBYTES);
    
}

void doFriends()
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
                  friendlist[i].friend_request_id = send_friendrequest(friendlist[i].client_id, friendip, info, info_size);
             }
             if(request == 1)
             {
                  friendlist[i].status = 2;
             }
        }
        if(friendlist[i].status == 2 || friendlist[i].status == 3)
        {
            IP_Port friendip = DHT_getfriendip(friendlist[i].client_id);
            if(is_cryptoconnected(friendlist[i].crypt_connection_id) == 0 && friendip.ip.i > 1)
            {
                 friendlist[i].crypt_connection_id = crypto_connect(friendlist[i].client_id, friendip);
            }
            if(is_cryptoconnected(friendlist[i].crypt_connection_id) == 3)//if connection is established.
            {
                 friendlist[i].status = 4;
            }
        }
        while(friendlist[i].status == 4)
        {
            len = read_cryptpacket(friendlist[i].crypt_connection_id, temp);
            if(len > 0)
            {
                 if(temp[0] == 64)
                 {
                     (*friend_message)(i, temp, len);
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

void doFriendRequest()
{
    uint8_t public_key[crypto_box_PUBLICKEYBYTES];
    uint8_t temp[MAX_DATA_SIZE];
    
    int len = handle_friendrequest(public_key, temp);
    if(len >= 0)
    {
        (*friend_request)(public_key, temp, len);

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
            printf("Received unhandled packet with length: %u\n", length);
        }
        else
        {
            printf("Received handled packet with length: %u\n", length);
        }
        //}
    }
    doDHT();
    doLossless_UDP();
    doNetCrypto();
    doFriendRequest();
    doFriends();
}
