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

#define MAX_ONION_SIZE MAX_DATA_SIZE

#define RETURN_1 (crypto_secretbox_NONCEBYTES + sizeof(IP_Port) + crypto_secretbox_MACBYTES)
#define RETURN_2 (crypto_secretbox_NONCEBYTES + sizeof(IP_Port) + crypto_secretbox_MACBYTES + RETURN_1)
#define RETURN_3 (crypto_secretbox_NONCEBYTES + sizeof(IP_Port) + crypto_secretbox_MACBYTES + RETURN_2)

#define SEND_BASE (crypto_box_PUBLICKEYBYTES + sizeof(IP_Port) + crypto_box_MACBYTES)
#define SEND_3 (crypto_box_NONCEBYTES + SEND_BASE + RETURN_2)
#define SEND_2 (crypto_box_NONCEBYTES + SEND_BASE*2 + RETURN_1)
#define SEND_1 (crypto_box_NONCEBYTES + SEND_BASE*3)

static int handle_send_initial(void *object, IP_Port source, uint8_t *packet, uint32_t length)
{
    Onion *onion = object;

    if (length > MAX_ONION_SIZE)
        return 1;

    if (length <= 1 + SEND_1)
        return 1;

    uint8_t plain[MAX_ONION_SIZE];

    int len = decrypt_data(packet + 1 + crypto_box_NONCEBYTES, onion->dht->self_secret_key, packet + 1,
                           packet + 1 + crypto_box_NONCEBYTES + crypto_box_PUBLICKEYBYTES,
                           length - (1 + crypto_box_NONCEBYTES + crypto_box_PUBLICKEYBYTES), plain);

    if ((uint32_t)len != length - (1 + crypto_box_NONCEBYTES + crypto_box_PUBLICKEYBYTES + crypto_box_MACBYTES))
        return 1;

    IP_Port send_to;
    memcpy(&send_to, plain, sizeof(IP_Port));
    uint8_t data[MAX_ONION_SIZE];
    data[0] = NET_PACKET_ONION_SEND_1;
    memcpy(data + 1, packet + 1, crypto_box_NONCEBYTES);
    memcpy(data + 1 + crypto_box_NONCEBYTES, plain + sizeof(IP_Port), len - sizeof(IP_Port));
    uint8_t *ret_part = data + 1 + crypto_box_NONCEBYTES + (len - sizeof(IP_Port));
    new_nonce(ret_part);
    len = encrypt_data_symmetric(onion->secret_symmetric_key, ret_part, (uint8_t *)&source, sizeof(IP_Port),
                                 ret_part + crypto_secretbox_NONCEBYTES);

    if (len != sizeof(IP_Port) + crypto_secretbox_MACBYTES)
        return 1;

    uint32_t data_len = 1 + crypto_box_NONCEBYTES + (len - sizeof(IP_Port)) + len;

    if ((uint32_t)sendpacket(onion->net, send_to, data, data_len) != data_len)
        return 1;

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

    if (length > MAX_ONION_SIZE)
        return 1;

    if (length <= 1 + RETURN_3)
        return 1;

    uint8_t plain[sizeof(IP_Port) + RETURN_2];
    int len = decrypt_data_symmetric(onion->secret_symmetric_key, packet + 1, packet + 1 + crypto_secretbox_NONCEBYTES,
                                     sizeof(IP_Port) + RETURN_2 + crypto_secretbox_MACBYTES, plain);

    if ((uint32_t)len != sizeof(plain))
        return 1;

    IP_Port send_to;
    memcpy(&send_to, plain, sizeof(IP_Port));

    uint8_t data[MAX_ONION_SIZE];
    data[0] = NET_PACKET_ONION_RECV_2;
    memcpy(data + 1, plain + sizeof(IP_Port), RETURN_2);
    memcpy(data + 1 + RETURN_2, packet + 1 + RETURN_3, length - (1 + RETURN_3));
    uint32_t data_len = 1 + RETURN_2 + (length - (1 + RETURN_3));

    if ((uint32_t)sendpacket(onion->net, send_to, data, data_len) != data_len)
        return 1;

    return 0;
}

static int handle_recv_2(void *object, IP_Port source, uint8_t *packet, uint32_t length)
{
    Onion *onion = object;

    if (length > MAX_ONION_SIZE)
        return 1;

    if (length <= 1 + RETURN_2)
        return 1;

    uint8_t plain[sizeof(IP_Port) + RETURN_1];
    int len = decrypt_data_symmetric(onion->secret_symmetric_key, packet + 1, packet + 1 + crypto_secretbox_NONCEBYTES,
                                     sizeof(IP_Port) + RETURN_1 + crypto_secretbox_MACBYTES, plain);

    if ((uint32_t)len != sizeof(plain))
        return 1;

    IP_Port send_to;
    memcpy(&send_to, plain, sizeof(IP_Port));

    uint8_t data[MAX_ONION_SIZE];
    data[0] = NET_PACKET_ONION_RECV_1;
    memcpy(data + 1, plain + sizeof(IP_Port), RETURN_1);
    memcpy(data + 1 + RETURN_1, packet + 1 + RETURN_2, length - (1 + RETURN_2));
    uint32_t data_len = 1 + RETURN_1 + (length - (1 + RETURN_2));

    if ((uint32_t)sendpacket(onion->net, send_to, data, data_len) != data_len)
        return 1;

    return 0;
}

static int handle_recv_1(void *object, IP_Port source, uint8_t *packet, uint32_t length)
{
    Onion *onion = object;

    if (length > MAX_ONION_SIZE)
        return 1;

    if (length <= 1 + RETURN_1)
        return 1;

    IP_Port send_to;

    int len = decrypt_data_symmetric(onion->secret_symmetric_key, packet + 1, packet + 1 + crypto_secretbox_NONCEBYTES,
                                     sizeof(IP_Port) + crypto_secretbox_MACBYTES, (uint8_t *) &send_to);

    if ((uint32_t)len != sizeof(IP_Port))
        return 1;

    uint32_t data_len = length - (1 + RETURN_1);

    if ((uint32_t)sendpacket(onion->net, send_to, packet + (1 + RETURN_1), data_len) != data_len)
        return 1;

    return 0;
}


Onion *new_onion(DHT *dht)
{
    if (dht == NULL)
        return NULL;

    Onion *onion = calloc(1, sizeof(Onion));

    if (onion == NULL)
        return NULL;

    onion->dht = dht;
    onion->net = dht->c->lossless_udp->net;
    new_symmetric_key(onion->secret_symmetric_key);

    networking_registerhandler(onion->net, NET_PACKET_ONION_SEND_INITIAL, &handle_send_initial, onion);
    networking_registerhandler(onion->net, NET_PACKET_ONION_SEND_1, &handle_send_1, onion);
    networking_registerhandler(onion->net, NET_PACKET_ONION_SEND_2, &handle_send_2, onion);

    networking_registerhandler(onion->net, NET_PACKET_ONION_RECV_3, &handle_recv_3, onion);
    networking_registerhandler(onion->net, NET_PACKET_ONION_RECV_2, &handle_recv_2, onion);
    networking_registerhandler(onion->net, NET_PACKET_ONION_RECV_1, &handle_recv_1, onion);

    return onion;
}

void kill_onion(Onion *onion)
{
    networking_registerhandler(onion->net, NET_PACKET_ONION_SEND_INITIAL, NULL, NULL);
    networking_registerhandler(onion->net, NET_PACKET_ONION_SEND_1, NULL, NULL);
    networking_registerhandler(onion->net, NET_PACKET_ONION_SEND_2, NULL, NULL);

    networking_registerhandler(onion->net, NET_PACKET_ONION_RECV_3, NULL, NULL);
    networking_registerhandler(onion->net, NET_PACKET_ONION_RECV_2, NULL, NULL);
    networking_registerhandler(onion->net, NET_PACKET_ONION_RECV_1, NULL, NULL);

    free(onion);
}
