#include <stdlib.h>
#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <time.h>

#ifdef WIN32 //Put win32 includes here

#include <winsock2.h>
#include <windows.h>

#else //Linux includes

#include <fcntl.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <errno.h>

#endif


typedef union
{
    uint8_t c[4];
    uint16_t s[2];
    uint32_t i;
}IP;

typedef struct
{
    IP ip;
    uint16_t port;
    
}IP_Port;


typedef struct
{
    char client_id[32];
    IP_Port ip_port;
    uint32_t timestamp;
    
}Client_data;


typedef struct
{
    char client_id[32];
    Client_data client_list[8];
    
}Friend;

typedef struct
{
    IP_Port ip_port;
    uint32_t ping_id;
    uint32_t timestamp;
    
}Pinged;


//Add a new friend to the friends list
//client_id must be 32 bytes long.
void addfriend(char * client_id);

//Delete a friend from the friends list
//client_id must be 32 bytes long.
//returns 0 if success
//returns 1 if failure (client_id not in friends list)
char delfriend(char * client_id);


//Get ip of friend
//client_id must be 32 bytes long.
//ip must be 4 bytes long.
//port must be 2 bytes long.
//returns ip if success
//returns ip of 0 if failure (This means the friend is either offline of we have not found him yet.)
IP_Port getfriendip(char * client_id);


//Run this function at least a couple times per second (It's the main loop)
void doDHT();

//if we recieve a DHT packet we call this function so it can be handled.
void DHT_recvpacket(char * packet, uint32_t length);

//Use this function to bootstrap the client
//Sends a get nodes request to the given ip port
void bootstrap(IP_Port ip_port);


//TODO:
//Add functions to save and load the state(client list, friends list)


//Global variables

//Our client id
char self_client_id[32];

//Our UDP socket.
//We only use one so it's much easier to have it as a global variable
int sock;

Client_data client_list[32];

//Let's start with a static array for testing.
Friend friends_list[256];
uint16_t num_friends;

//The list of ip ports along with the ping_id of what we sent them and a timestamp
//TODO: make this more efficient looping up to 128 times is a bit...
Pinged pings[128];

Pinged send_nodes[64];
