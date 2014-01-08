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

typedef struct {
    Node_format clients_list[MAX_ONION_CLIENTS];


} Onion_Friend;

typedef struct {
    DHT     *dht;
    Networking_Core *net;
    Onion_Friend    *friends_list;
    uint16_t       num_friends;

    Node_format clients_annouce_list[MAX_ONION_CLIENTS];
} Onion_Client;

int onion_addfriend(Onion_Client *onion_c, uint8_t *client_id);

int onion_delfriend(Onion_Client *onion_c, uint8_t *client_id);

int onion_getfriendip(Onion_Client *onion_c, uint8_t *client_id, IP_Port *ip_port);


void do_onion_client(Onion_Client *onion_c);

Onion_Client *new_onion_client(DHT *dht);

void kill_onion_client(Onion_Client *onion_c);

#endif
