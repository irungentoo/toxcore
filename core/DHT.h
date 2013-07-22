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

#include "net_crypto.h"

#ifdef __cplusplus
extern "C" {
#endif

/* Current time, unix format */
#define unix_time() ((uint32_t)time(NULL))

/* size of the client_id in bytes */
#define CLIENT_ID_SIZE crypto_box_PUBLICKEYBYTES



/* Add a new friend to the friends list
   client_id must be CLIENT_ID_SIZE bytes long.
   returns 0 if success
   returns 1 if failure (friends list is full) */
int DHT_addfriend(uint8_t * client_id);

/* Delete a friend from the friends list
   client_id must be CLIENT_ID_SIZE bytes long.
   returns 0 if success
   returns 1 if failure (client_id not in friends list) */
int DHT_delfriend(uint8_t * client_id);


/* Get ip of friend
   client_id must be CLIENT_ID_SIZE bytes long.
   ip must be 4 bytes long.
   port must be 2 bytes long.
   returns ip if success
   returns ip of 0 if failure (This means the friend is either offline or we have not found him yet.)
   returns ip of 1 if friend is not in list. */
IP_Port DHT_getfriendip(uint8_t * client_id);


/* Run this function at least a couple times per second (It's the main loop) */
void doDHT();

/* if we receive a DHT packet we call this function so it can be handled.
   return 0 if packet is handled correctly.
   return 1 if it didn't handle the packet or if the packet was shit. */
int DHT_handlepacket(uint8_t * packet, uint32_t length, IP_Port source);

/* Use this function to bootstrap the client
   Sends a get nodes request to the given node with ip port and public_key */
void DHT_bootstrap(IP_Port ip_port, uint8_t * public_key);



/* ROUTING FUNCTIONS */

/* send the given packet to node with client_id
   returns -1 if failure */
int route_packet(uint8_t * client_id, uint8_t * packet, uint32_t length);

/* Send the following packet to everyone who tells us they are connected to friend_id
   returns the number of nodes it sent the packet to */
int route_tofriend(uint8_t * friend_id, uint8_t * packet, uint32_t length);



/* NAT PUNCHING FUNCTIONS */

/* Puts all the different ips returned by the nodes for a friend_id into array ip_portlist 
   ip_portlist must be at least MAX_FRIEND_CLIENTS big
   returns the number of ips returned
   returns -1 if no such friend*/
int friend_ips(IP_Port * ip_portlist, uint8_t * friend_id);



/* SAVE/LOAD functions */

/* get the size of the DHT (for saving) */
uint32_t DHT_size();

/* save the DHT in data where data is an array of size DHT_size() */
void DHT_save(uint8_t * data);

/* load the DHT from data of size size;
   return -1 if failure
   return 0 if success */
int DHT_load(uint8_t * data, uint32_t size);

/* returns 0 if we are not connected to the DHT
   returns 1 if we are */
int DHT_isconnected();

#ifdef __cplusplus
}
#endif

#endif
