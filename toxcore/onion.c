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
#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "onion.h"

#define MAX_ONION_SIZE MAX_DATA_SIZE

#define RETURN_1 ONION_RETURN_1
#define RETURN_2 ONION_RETURN_2
#define RETURN_3 ONION_RETURN_3

#define SEND_BASE ONION_SEND_BASE
#define SEND_3 ONION_SEND_3
#define SEND_2 ONION_SEND_2
#define SEND_1 ONION_SEND_1

/* Create and send a onion packet.
 *
 * nodes is a list of 4 nodes, the packet will route through nodes 0, 1, 2 and the data
 * with length length will arrive at 3.
 *
 * return -1 on failure.
 * return 0 on success.
 */
int send_onion_packet(DHT *dht, Node_format *nodes, uint8_t *data, uint32_t length)
{
    if (1 + length + SEND_1 > MAX_ONION_SIZE || length == 0)
        return -1;

    uint8_t step1[sizeof(IP_Port) + length];
    memcpy(step1, &nodes[3].ip_port, sizeof(IP_Port));
    memcpy(step1 + sizeof(IP_Port), data, length);

    uint8_t nonce[crypto_box_NONCEBYTES];
    new_nonce(nonce);
    uint8_t random_public_key[crypto_box_PUBLICKEYBYTES];
    uint8_t random_secret_key[crypto_box_SECRETKEYBYTES];
    crypto_box_keypair(random_public_key, random_secret_key);

    uint8_t step2[sizeof(IP_Port) + SEND_BASE + length];
    memcpy(step2, &nodes[2].ip_port, sizeof(IP_Port));
    memcpy(step2 + sizeof(IP_Port), random_public_key, crypto_box_PUBLICKEYBYTES);

    int len = encrypt_data(nodes[2].client_id, random_secret_key, nonce,
                           step1, sizeof(step1), step2 + sizeof(IP_Port) + crypto_box_PUBLICKEYBYTES);

    if ((uint32_t)len != sizeof(IP_Port) + length + crypto_box_MACBYTES)
        return -1;

    crypto_box_keypair(random_public_key, random_secret_key);
    uint8_t step3[sizeof(IP_Port) + SEND_BASE * 2 + length];
    memcpy(step3, &nodes[1].ip_port, sizeof(IP_Port));
    memcpy(step3 + sizeof(IP_Port), random_public_key, crypto_box_PUBLICKEYBYTES);
    len = encrypt_data(nodes[1].client_id, random_secret_key, nonce,
                       step2, sizeof(step2), step3 + sizeof(IP_Port) + crypto_box_PUBLICKEYBYTES);

    if ((uint32_t)len != sizeof(IP_Port) + SEND_BASE + length + crypto_box_MACBYTES)
        return -1;

    uint8_t packet[1 + length + SEND_1];
    packet[0] = NET_PACKET_ONION_SEND_INITIAL;
    memcpy(packet + 1, nonce, crypto_box_NONCEBYTES);
    memcpy(packet + 1 + crypto_box_NONCEBYTES, dht->self_public_key, crypto_box_PUBLICKEYBYTES);

    len = encrypt_data(nodes[0].client_id, dht->self_secret_key, nonce,
                       step3, sizeof(step3), packet + 1 + crypto_box_NONCEBYTES + crypto_box_PUBLICKEYBYTES);

    if ((uint32_t)len != sizeof(IP_Port) + SEND_BASE * 2 + length + crypto_box_MACBYTES)
        return -1;

    if ((uint32_t)sendpacket(dht->c->lossless_udp->net, nodes[0].ip_port, packet, sizeof(packet)) != sizeof(packet))
        return -1;

    return 0;
}
/* Create and send a onion response sent initially to dest with.
 *
 * return -1 on failure.
 * return 0 on success.
 */
int send_onion_response(Networking_Core *net, IP_Port dest, uint8_t *data, uint32_t length, uint8_t *ret)
{
    uint8_t packet[1 + RETURN_3 + length];
    packet[0] = NET_PACKET_ONION_RECV_3;
    memcpy(packet + 1, ret, RETURN_3);
    memcpy(packet + 1 + RETURN_3, data, length);

    if ((uint32_t)sendpacket(net, dest, packet, sizeof(packet)) != sizeof(packet))
        return -1;

    return 0;
}

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
    uint32_t data_len = 1 + crypto_box_NONCEBYTES + (len - sizeof(IP_Port));
    uint8_t *ret_part = data + data_len;
    new_nonce(ret_part);
    len = encrypt_data_symmetric(onion->secret_symmetric_key, ret_part, (uint8_t *)&source, sizeof(IP_Port),
                                 ret_part + crypto_secretbox_NONCEBYTES);

    if (len != sizeof(IP_Port) + crypto_secretbox_MACBYTES)
        return 1;

    data_len += crypto_secretbox_NONCEBYTES + len;

    if ((uint32_t)sendpacket(onion->net, send_to, data, data_len) != data_len)
        return 1;

    return 0;
}

static int handle_send_1(void *object, IP_Port source, uint8_t *packet, uint32_t length)
{
    Onion *onion = object;

    if (length > MAX_ONION_SIZE)
        return 1;

    if (length <= 1 + SEND_2)
        return 1;

    uint8_t plain[MAX_ONION_SIZE];

    int len = decrypt_data(packet + 1 + crypto_box_NONCEBYTES, onion->dht->self_secret_key, packet + 1,
                           packet + 1 + crypto_box_NONCEBYTES + crypto_box_PUBLICKEYBYTES,
                           length - (1 + crypto_box_NONCEBYTES + crypto_box_PUBLICKEYBYTES + RETURN_1), plain);

    if ((uint32_t)len != length - (1 + crypto_box_NONCEBYTES + crypto_box_PUBLICKEYBYTES + RETURN_1 + crypto_box_MACBYTES))
        return 1;

    IP_Port send_to;
    memcpy(&send_to, plain, sizeof(IP_Port));
    uint8_t data[MAX_ONION_SIZE];
    data[0] = NET_PACKET_ONION_SEND_2;
    memcpy(data + 1, packet + 1, crypto_box_NONCEBYTES);
    memcpy(data + 1 + crypto_box_NONCEBYTES, plain + sizeof(IP_Port), len - sizeof(IP_Port));
    uint32_t data_len = 1 + crypto_box_NONCEBYTES + (len - sizeof(IP_Port));
    uint8_t *ret_part = data + data_len;
    new_nonce(ret_part);
    uint8_t ret_data[RETURN_1 + sizeof(IP_Port)];
    memcpy(ret_data, &source, sizeof(IP_Port));
    memcpy(ret_data + sizeof(IP_Port), packet + (length - RETURN_1), RETURN_1);
    len = encrypt_data_symmetric(onion->secret_symmetric_key, ret_part, ret_data, sizeof(ret_data),
                                 ret_part + crypto_secretbox_NONCEBYTES);

    if (len != RETURN_2 - crypto_secretbox_NONCEBYTES)
        return 1;

    data_len += crypto_secretbox_NONCEBYTES + len;

    if ((uint32_t)sendpacket(onion->net, send_to, data, data_len) != data_len)
        return 1;

    return 0;
}

static int handle_send_2(void *object, IP_Port source, uint8_t *packet, uint32_t length)
{
    Onion *onion = object;

    if (length > MAX_ONION_SIZE)
        return 1;

    if (length <= 1 + SEND_3)
        return 1;

    uint8_t plain[MAX_ONION_SIZE];

    int len = decrypt_data(packet + 1 + crypto_box_NONCEBYTES, onion->dht->self_secret_key, packet + 1,
                           packet + 1 + crypto_box_NONCEBYTES + crypto_box_PUBLICKEYBYTES,
                           length - (1 + crypto_box_NONCEBYTES + crypto_box_PUBLICKEYBYTES + RETURN_2), plain);

    if ((uint32_t)len != length - (1 + crypto_box_NONCEBYTES + crypto_box_PUBLICKEYBYTES + RETURN_2 + crypto_box_MACBYTES))
        return 1;

    IP_Port send_to;
    memcpy(&send_to, plain, sizeof(IP_Port));
    uint8_t data[MAX_ONION_SIZE];
    memcpy(data, plain + sizeof(IP_Port), len - sizeof(IP_Port));
    uint32_t data_len = (len - sizeof(IP_Port));
    uint8_t *ret_part = data + (len - sizeof(IP_Port));
    new_nonce(ret_part);
    uint8_t ret_data[RETURN_2 + sizeof(IP_Port)];
    memcpy(ret_data, &source, sizeof(IP_Port));
    memcpy(ret_data + sizeof(IP_Port), packet + (length - RETURN_2), RETURN_2);
    len = encrypt_data_symmetric(onion->secret_symmetric_key, ret_part, ret_data, sizeof(ret_data),
                                 ret_part + crypto_secretbox_NONCEBYTES);

    if (len != RETURN_3 - crypto_secretbox_NONCEBYTES)
        return 1;

    data_len += RETURN_3;

    if ((uint32_t)sendpacket(onion->net, send_to, data, data_len) != data_len)
        return 1;

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
    if (onion == NULL)
        return;

    networking_registerhandler(onion->net, NET_PACKET_ONION_SEND_INITIAL, NULL, NULL);
    networking_registerhandler(onion->net, NET_PACKET_ONION_SEND_1, NULL, NULL);
    networking_registerhandler(onion->net, NET_PACKET_ONION_SEND_2, NULL, NULL);

    networking_registerhandler(onion->net, NET_PACKET_ONION_RECV_3, NULL, NULL);
    networking_registerhandler(onion->net, NET_PACKET_ONION_RECV_2, NULL, NULL);
    networking_registerhandler(onion->net, NET_PACKET_ONION_RECV_1, NULL, NULL);

    free(onion);
}
