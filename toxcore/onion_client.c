/*
* onion_client.c -- Implementation of the client part of docs/Prevent_Tracking.txt
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
#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "onion_client.h"


static int handle_announce_response(void *object, IP_Port source, uint8_t *packet, uint32_t length)
{
    Onion_Client *onion_c = object;

    return 0;
}

static int handle_data_response(void *object, IP_Port source, uint8_t *packet, uint32_t length)
{
    Onion_Client *onion_c = object;

    return 0;
}

/* Takes 3 random nodes that we know and puts them in nodes
 *
 * nodes must be longer than 3.
 *
 * return -1 on failure
 * return 0 on success
 *
 */
int random_path(Onion_Client *onion_c, Node_format *nodes)
{


}

void do_onion_client(Onion_Client *onion_c)
{


}

Onion_Client *new_onion_client(DHT *dht)
{
    if (dht == NULL)
        return NULL;

    Onion_Client *onion_c = calloc(1, sizeof(Onion_Client));

    if (onion_c == NULL)
        return NULL;

    onion_c->dht = dht;
    onion_c->net = dht->c->lossless_udp->net;

    networking_registerhandler(onion_c->net, NET_PACKET_ANNOUNCE_RESPONSE, &handle_announce_response, onion_c);
    networking_registerhandler(onion_c->net, NET_PACKET_ONION_DATA_RESPONSE, &handle_data_response, onion_c);

    return onion_c;
}

void kill_onion_client(Onion_Client *onion_c)
{
    networking_registerhandler(onion_c->net, NET_PACKET_ANNOUNCE_RESPONSE, NULL, NULL);
    networking_registerhandler(onion_c->net, NET_PACKET_ONION_DATA_RESPONSE, NULL, NULL);
    free(onion_c);
}
