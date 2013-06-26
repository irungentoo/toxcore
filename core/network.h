/* network.h
* 
* Datatypes, functions and includes for the core networking.
* 
*/
 

#ifndef NETWORK_H 
#define NETWORK_H 

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
    int16_t family;
    uint16_t port;
    IP ip;
    uint8_t zeroes[8];
    #ifdef ENABLE_IPV6
    uint8_t zeroes2[12];
    #endif
}ADDR;




//Basic network functions:

//Function to send packet(data) of length length to ip_port
int sendpacket(IP_Port ip_port, char * data, uint32_t length);

//Function to recieve data, ip and port of sender is put into ip_port
//the packet data into data
//the packet length into length.
int recievepacket(IP_Port * ip_port, char * data, uint32_t * length);

//initialize networking
//bind to ip and port
//ip must be in network order EX: 127.0.0.1 = (7F000001)
//port is in host byte order (this means don't worry about it)
//returns 0 if no problems
//TODO: add something to check if there are errors
int init_networking(IP ip ,uint16_t port);
#endif