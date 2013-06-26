/* DHT.h
* 
* An implementation of the DHT as seen in docs/DHT.txt
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


#ifndef DHT_H 
#define DHT_H 

#include "network.h"

//Current time, unix format
#define unix_time() ((uint32_t)time(NULL))

//size of the client_id in bytes
#define CLIENT_ID_SIZE 32

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


//Add a new friend to the friends list
//client_id must be CLIENT_ID_SIZE bytes long.
//returns 0 if success
//returns 1 if failure (friends list is full)
int addfriend(char * client_id);

//Delete a friend from the friends list
//client_id must be CLIENT_ID_SIZE bytes long.
//returns 0 if success
//returns 1 if failure (client_id not in friends list)
int delfriend(char * client_id);


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
//Return 0 if packet is handled correctly.
//return 1 if it didn't handle the packet or if the packet was shit.
int DHT_handlepacket(char * packet, uint32_t length, IP_Port source);

//Use this function to bootstrap the client
//Sends a get nodes request to the given ip port
void bootstrap(IP_Port ip_port);


//TODO:
//Add functions to save and load the state(client list, friends list)


//Global variables

//Our client id
extern char self_client_id[CLIENT_ID_SIZE];


//TODO: Move these out of here and put them into the .c file.
//A list of the clients mathematically closest to ours.
#define LCLIENT_LIST 32
Client_data close_clientlist[LCLIENT_LIST];


//Hard maximum number of friends 
#define MAX_FRIENDS 256

//Let's start with a static array for testing.
Friend friends_list[MAX_FRIENDS];
uint16_t num_friends;

//The list of ip ports along with the ping_id of what we sent them and a timestamp
#define LPING_ARRAY 128

Pinged pings[LPING_ARRAY];

#define LSEND_NODES_ARRAY LPING_ARRAY/2

Pinged send_nodes[LSEND_NODES_ARRAY];


#endif 