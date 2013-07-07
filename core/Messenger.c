/* Messenger.c
* 
* An implementation of a simple text chat only messenger on the tox network core.
* 
*/

#include "Messenger.h"
 
 
typedef struct
{
    uint8_t client_id[CLIENT_ID_SIZE];
    
    
}Friend;
 
#define MAX_NUM_FRIENDS 256

Friend friendlist[MAX_NUM_FRIENDS];
 
//add a friend
//returns the friend number if success
//return -1 if failure.
int m_addfriend(uint8_t * client_id)
{
    
    //add friend to the DHT
    addfriend(uint8_t * client_id);
    
    send_friendrequest(uint8_t * public_key, IP_Port ip_port, uint8_t * data, uint32_t length);
    
}

//remove a friend
int m_delfriend(int friendnumber)
{
    //delete friend from DHT
    delfriend(uint8_t * client_id);
    
}


//return 1 if friend is online
//return 0 if he is not
int m_friendonline(int friendnumber)
{
    
    
}


//send a text chat message to a friend.
int m_sendmessage(int friendnumber)
{
    write_cryptpacket(int crypt_connection_id, uint8_t * data, uint32_t length);
    
}


#define PORT 33445
//run this at startup
void initMessenger();
{
    new_keys();
    IP ip;
    ip.i = 0;
    init_networking(ip, PORT);
    
}

//the main loop that needs to be run at least 200 times per second.
void doMessenger();
{
    IP_Port ip_port;
    uint8_t data[MAX_UDP_PACKET_SIZE];
    uint32_t length;
    while(recievepacket(&ip_port, data, &length) != -1)
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
}