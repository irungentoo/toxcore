/*
* onion.c -- Implementation of the onion part of docs/Prevent_Tracking.txt
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

#include "onion.h"

static int handle_send_initial(void *object, IP_Port source, uint8_t *packet, uint32_t length)
{
    Onion *onion = object;

    return 0;
}

static int handle_send_1(void *object, IP_Port source, uint8_t *packet, uint32_t length)
{
    Onion *onion = object;

    return 0;
}

static int handle_send_2(void *object, IP_Port source, uint8_t *packet, uint32_t length)
{
    Onion *onion = object;

    return 0;
}


static int handle_recv_3(void *object, IP_Port source, uint8_t *packet, uint32_t length)
{
    Onion *onion = object;

    return 0;
}

static int handle_recv_2(void *object, IP_Port source, uint8_t *packet, uint32_t length)
{
    Onion *onion = object;

    return 0;
}

static int handle_recv_1(void *object, IP_Port source, uint8_t *packet, uint32_t length)
{
    Onion *onion = object;

    return 0;
}



Onion *new_onion(DHT *dht)
{
    if (dht == NULL)
        return NULL;

    Onion *onion = calloc(1, sizeof(Onion));

    if (onion == NULL)
        return NULL;

    new_symmetric_key(onion->secret_symmetric_key);

    networking_registerhandler(dht->c->lossless_udp->net, NET_PACKET_ONION_SEND_INITIAL, &handle_send_initial, onion);
    networking_registerhandler(dht->c->lossless_udp->net, NET_PACKET_ONION_SEND_1, &handle_send_1, onion);
    networking_registerhandler(dht->c->lossless_udp->net, NET_PACKET_ONION_SEND_1, &handle_send_2, onion);

    networking_registerhandler(dht->c->lossless_udp->net, NET_PACKET_ONION_RECV_3, &handle_recv_3, onion);
    networking_registerhandler(dht->c->lossless_udp->net, NET_PACKET_ONION_RECV_2, &handle_recv_2, onion);
    networking_registerhandler(dht->c->lossless_udp->net, NET_PACKET_ONION_RECV_1, &handle_recv_1, onion);
    
    return onion;
}

void kill_onion(Onion *onion)
{
    networking_registerhandler(onion->dht->c->lossless_udp->net, NET_PACKET_ONION_SEND_INITIAL, NULL, NULL);
    networking_registerhandler(onion->dht->c->lossless_udp->net, NET_PACKET_ONION_SEND_1, NULL, NULL);
    networking_registerhandler(onion->dht->c->lossless_udp->net, NET_PACKET_ONION_SEND_1, NULL, NULL);

    networking_registerhandler(onion->dht->c->lossless_udp->net, NET_PACKET_ONION_RECV_3, NULL, NULL);
    networking_registerhandler(onion->dht->c->lossless_udp->net, NET_PACKET_ONION_RECV_2, NULL, NULL);
    networking_registerhandler(onion->dht->c->lossless_udp->net, NET_PACKET_ONION_RECV_1, NULL, NULL);

    free(onion);
}
