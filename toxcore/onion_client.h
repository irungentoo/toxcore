/*
* onion_client.h -- Implementation of the client part of docs/Prevent_Tracking.txt
*                   (The part that uses the onion stuff to connect to the friend)
*
*  Copyright (C) 2013 Tox project All Rights Reserved.
*
*  This file is part of Tox.
*
*  Tox is free software: you can redistribute it and/or modify
*  it under the terms of the GNU General Public License as published by
*  the Free Software Foundation, either version 3 of the License, or
*  (at your option) any later version.
*
*  Tox is distributed in the hope that it will be useful,
*  but WITHOUT ANY WARRANTY; without even the implied warranty of
*  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
*  GNU General Public License for more details.
*
*  You should have received a copy of the GNU General Public License
*  along with Tox.  If not, see <http://www.gnu.org/licenses/>.
*
*/

#ifndef ONION_CLIENT_H
#define ONION_CLIENT_H

#include "onion_announce.h"

#define MAX_ONION_CLIENTS 8
#define ONION_NODE_TIMEOUT 200

/* The interval in seconds at which to tell our friends where we are */
#define ONION_FAKEID_INTERVAL 60

typedef struct {
    uint8_t     client_id[CLIENT_ID_SIZE];
    IP_Port     ip_port;
    uint8_t     ping_id[ONION_PING_ID_SIZE];
    uint64_t    timestamp;

    uint64_t    last_pinged;
} Onion_Node;

typedef struct {
    uint8_t status; /* 0 if friend is not valid, 1 if friend is valid.*/

    uint8_t fake_client_id[crypto_box_PUBLICKEYBYTES];
    uint8_t real_client_id[crypto_box_PUBLICKEYBYTES];

    Onion_Node clients_list[MAX_ONION_CLIENTS];
    uint8_t temp_public_key[crypto_box_PUBLICKEYBYTES];
    uint8_t temp_secret_key[crypto_box_SECRETKEYBYTES];

    uint64_t last_fakeid_sent;
} Onion_Friend;

typedef int (*oniondata_handler_callback)(void *object, uint8_t *source_pubkey, uint8_t *data, uint32_t len);

typedef struct {
    DHT     *dht;
    Networking_Core *net;
    Onion_Friend    *friends_list;
    uint16_t       num_friends;

    Onion_Node clients_announce_list[MAX_ONION_CLIENTS];

    uint8_t secret_symmetric_key[crypto_secretbox_KEYBYTES];
    uint64_t last_run;

    struct {
        oniondata_handler_callback function;
        void *object;
    } Onion_Data_Handlers[256];
} Onion_Client;

/* Add a friend who we want to connect to.
 *
 * return -1 on failure.
 * return the friend number on success or if the friend was already added.
 */
int onion_friend_num(Onion_Client *onion_c, uint8_t *client_id);

/* Add a friend who we want to connect to.
 *
 * return -1 on failure.
 * return the friend number on success.
 */
int onion_addfriend(Onion_Client *onion_c, uint8_t *client_id);

/* Delete a friend.
 *
 * return -1 on failure.
 * return the deleted friend number on success.
 */
int onion_delfriend(Onion_Client *onion_c, int friend_num);

/* Get the ip of friend friendnum and put it in ip_port
 *
 *  return -1, -- if client_id does NOT refer to a friend
 *  return  0, -- if client_id refers to a friend and we failed to find the friend (yet)
 *  return  1, ip if client_id refers to a friend and we found him
 *
 */
int onion_getfriendip(Onion_Client *onion_c, int friend_num, IP_Port *ip_port);

/* Takes 3 random nodes that we know and puts them in nodes
 *
 * nodes must be longer than 3.
 *
 * return -1 on failure
 * return 0 on success
 *
 */
int random_path(Onion_Client *onion_c, Node_format *nodes);

/* Send data of length length to friendnum.
 * This data will be recieved by the friend using the Onion_Data_Handlers callbacks.
 *
 * Even if this function succeeds, the friend might not recieve any data.
 *
 * return the number of packets sent on success
 * return -1 on failure.
 */
int send_onion_data(Onion_Client *onion_c, int friend_num, uint8_t *data, uint32_t length);

/* Function to call when onion data packet with contents beginning with byte is received. */
void oniondata_registerhandler(Onion_Client *onion_c, uint8_t byte, oniondata_handler_callback cb, void *object);

void do_onion_client(Onion_Client *onion_c);

Onion_Client *new_onion_client(DHT *dht);

void kill_onion_client(Onion_Client *onion_c);

#endif
