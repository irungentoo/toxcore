#ifndef DHT_H 
#define DHT_H 

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

//Current time, unix format
#define unix_time() ((uint32_t)time(NULL))

//size of the client_id in bytes
#define CLIENT_ID_SIZE 32

#define MAX_UDP_PACKET_SIZE 65507

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
    //not used for anything right now
    uint16_t padding; 
}IP_Port;


typedef struct
{
    char client_id[CLIENT_ID_SIZE];
    IP_Port ip_port;
    uint32_t timestamp;
    
}Client_data;
//maximum number of clients stored per friend.
#define MAX_FRIEND_CLIENTS 8
typedef struct
{
    char client_id[CLIENT_ID_SIZE];
    Client_data client_list[MAX_FRIEND_CLIENTS];
    
}Friend;


typedef struct
{
    char client_id[CLIENT_ID_SIZE];
    IP_Port ip_port;
}Node_format;

typedef struct
{
    IP_Port ip_port;
    uint32_t ping_id;
    uint32_t timestamp;
    
}Pinged;


typedef struct
{
    int16_t family;
    uint16_t port;
    IP ip;
    uint8_t zeroes[8];
    #ifdef ENABLE_IPV6
    uint8_t zeroes2[12];
    #endif
}ADDR;



//Add a new friend to the friends list
//client_id must be CLIENT_ID_SIZE bytes long.
void addfriend(char * client_id);

//Delete a friend from the friends list
//client_id must be CLIENT_ID_SIZE bytes long.
//returns 0 if success
//returns 1 if failure (client_id not in friends list)
char delfriend(char * client_id);


//Get ip of friend
//client_id must be CLIENT_ID_SIZE bytes long.
//ip must be 4 bytes long.
//port must be 2 bytes long.
//returns ip if success
//returns ip of 0 if failure (This means the friend is either offline or we have not found him yet.)
//returns ip of 1 if friend is not in list.
IP_Port getfriendip(char * client_id);


//Run this function at least a couple times per second (It's the main loop)
void doDHT();

//if we recieve a DHT packet we call this function so it can be handled.
//Return 0 if packet is handled correctly or if the packet was shit.
//return 1 if it didn't handle the packet.
int DHT_recvpacket(char * packet, uint32_t length, IP_Port source);

//Use this function to bootstrap the client
//Sends a get nodes request to the given ip port
void bootstrap(IP_Port ip_port);


//TODO:
//Add functions to save and load the state(client list, friends list)


//Global variables

//Our client id
char self_client_id[CLIENT_ID_SIZE];

//Our UDP socket.
//We only use one so it's much easier to have it as a global variable
int sock;

//A list of the clients mathematically closest to ours.
#define LCLIENT_LIST 32
Client_data close_clientlist[LCLIENT_LIST];


//Let's start with a static array for testing.
Friend friends_list[256];
uint16_t num_friends;

//The list of ip ports along with the ping_id of what we sent them and a timestamp
#define LPING_ARRAY 128

Pinged pings[LPING_ARRAY];

#define LSEND_NODES_ARRAY LPING_ARRAY/2

Pinged send_nodes[LSEND_NODES_ARRAY];


//Basic network functions:
//TODO: put them somewhere else than here

//Function to send packet(data) of length length to ip_port
int sendpacket(IP_Port ip_port, char * data, uint32_t length);

//Function to recieve data, ip and port of sender is put into ip_port
//the packet data into data
//the packet length into length.
int recievepacket(IP_Port * ip_port, char * data, uint32_t * length);

#endif 