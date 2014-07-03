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
#include "util.h"

#define RETURN_1 ONION_RETURN_1
#define RETURN_2 ONION_RETURN_2
#define RETURN_3 ONION_RETURN_3

#define SEND_BASE ONION_SEND_BASE
#define SEND_3 ONION_SEND_3
#define SEND_2 ONION_SEND_2
#define SEND_1 ONION_SEND_1

/* Change symmetric keys every hour to make paths expire eventually. */
#define KEY_REFRESH_INTERVAL (60 * 60)
static void change_symmetric_key(Onion *onion)
{
    if (is_timeout(onion->timestamp, KEY_REFRESH_INTERVAL)) {
        new_symmetric_key(onion->secret_symmetric_key);
        onion->timestamp = unix_time();
    }
}

/* Create a new onion path.
 *
 * Create a new onion path out of nodes (nodes is a list of 3 nodes)
 *
 * new_path must be an empty memory location of atleast Onion_Path size.
 *
 * return -1 on failure.
 * return 0 on success.
 */
int create_onion_path(const DHT *dht, Onion_Path *new_path, const Node_format *nodes)
{
    if (!new_path || !nodes)
        return -1;

    encrypt_precompute(nodes[0].client_id, dht->self_secret_key, new_path->shared_key1);
    memcpy(new_path->public_key1, dht->self_public_key, crypto_box_PUBLICKEYBYTES);

    uint8_t random_public_key[crypto_box_PUBLICKEYBYTES];
    uint8_t random_secret_key[crypto_box_SECRETKEYBYTES];

    crypto_box_keypair(random_public_key, random_secret_key);
    encrypt_precompute(nodes[1].client_id, random_secret_key, new_path->shared_key2);
    memcpy(new_path->public_key2, random_public_key, crypto_box_PUBLICKEYBYTES);

    crypto_box_keypair(random_public_key, random_secret_key);
    encrypt_precompute(nodes[2].client_id, random_secret_key, new_path->shared_key3);
    memcpy(new_path->public_key3, random_public_key, crypto_box_PUBLICKEYBYTES);

    new_path->ip_port1 = nodes[0].ip_port;
    new_path->ip_port2 = nodes[1].ip_port;
    new_path->ip_port3 = nodes[2].ip_port;

    /* to_net_family(&new_path->ip_port1.ip); */
    to_net_family(&new_path->ip_port2.ip);
    to_net_family(&new_path->ip_port3.ip);

    return 0;
}

/* Create a onion packet.
 *
 * Use Onion_Path path to create packet for data of length to dest.
 * Maximum length of data is ONION_MAX_DATA_SIZE.
 * packet should be at least ONION_MAX_PACKET_SIZE big.
 *
 * return -1 on failure.
 * return length of created packet on success.
 */
int create_onion_packet(uint8_t *packet, uint16_t max_packet_length, const Onion_Path *path, IP_Port dest,
                        const uint8_t *data, uint32_t length)
{
    if (1 + length + SEND_1 > max_packet_length || length == 0)
        return -1;

    to_net_family(&dest.ip);
    uint8_t step1[SIZE_IPPORT + length];


    ipport_pack(step1, &dest);
    memcpy(step1 + SIZE_IPPORT, data, length);

    uint8_t nonce[crypto_box_NONCEBYTES];
    random_nonce(nonce);

    uint8_t step2[SIZE_IPPORT + SEND_BASE + length];
    ipport_pack(step2, &path->ip_port3);
    memcpy(step2 + SIZE_IPPORT, path->public_key3, crypto_box_PUBLICKEYBYTES);

    int len = encrypt_data_symmetric(path->shared_key3, nonce, step1, sizeof(step1),
                                     step2 + SIZE_IPPORT + crypto_box_PUBLICKEYBYTES);

    if ((uint32_t)len != SIZE_IPPORT + length + crypto_box_MACBYTES)
        return -1;

    uint8_t step3[SIZE_IPPORT + SEND_BASE * 2 + length];
    ipport_pack(step3, &path->ip_port2);
    memcpy(step3 + SIZE_IPPORT, path->public_key2, crypto_box_PUBLICKEYBYTES);
    len = encrypt_data_symmetric(path->shared_key2, nonce, step2, sizeof(step2),
                                 step3 + SIZE_IPPORT + crypto_box_PUBLICKEYBYTES);

    if ((uint32_t)len != SIZE_IPPORT + SEND_BASE + length + crypto_box_MACBYTES)
        return -1;

    packet[0] = NET_PACKET_ONION_SEND_INITIAL;
    memcpy(packet + 1, nonce, crypto_box_NONCEBYTES);
    memcpy(packet + 1 + crypto_box_NONCEBYTES, path->public_key1, crypto_box_PUBLICKEYBYTES);

    len = encrypt_data_symmetric(path->shared_key1, nonce, step3, sizeof(step3),
                                 packet + 1 + crypto_box_NONCEBYTES + crypto_box_PUBLICKEYBYTES);

    if ((uint32_t)len != SIZE_IPPORT + SEND_BASE * 2 + length + crypto_box_MACBYTES)
        return -1;

    return 1 + crypto_box_NONCEBYTES + crypto_box_PUBLICKEYBYTES + len;
}

/* Create and send a onion packet.
 *
 * Use Onion_Path path to send data of length to dest.
 * Maximum length of data is ONION_MAX_DATA_SIZE.
 *
 * return -1 on failure.
 * return 0 on success.
 */
int send_onion_packet(Networking_Core *net, const Onion_Path *path, IP_Port dest, const uint8_t *data, uint32_t length)
{
    uint8_t packet[ONION_MAX_PACKET_SIZE];
    int len = create_onion_packet(packet, sizeof(packet), path, dest, data, length);

    if (len == -1)
        return -1;

    if (sendpacket(net, path->ip_port1, packet, len) != len)
        return -1;

    return 0;
}

/* Create and send a onion response sent initially to dest with.
 * Maximum length of data is ONION_RESPONSE_MAX_DATA_SIZE.
 *
 * return -1 on failure.
 * return 0 on success.
 */
int send_onion_response(Networking_Core *net, IP_Port dest, const uint8_t *data, uint32_t length, const uint8_t *ret)
{
    if (length > ONION_RESPONSE_MAX_DATA_SIZE || length == 0)
        return -1;

    uint8_t packet[1 + RETURN_3 + length];
    packet[0] = NET_PACKET_ONION_RECV_3;
    memcpy(packet + 1, ret, RETURN_3);
    memcpy(packet + 1 + RETURN_3, data, length);

    if ((uint32_t)sendpacket(net, dest, packet, sizeof(packet)) != sizeof(packet))
        return -1;

    return 0;
}

static int handle_send_initial(void *object, IP_Port source, const uint8_t *packet, uint32_t length)
{
    Onion *onion = object;

    if (length > ONION_MAX_PACKET_SIZE)
        return 1;

    if (length <= 1 + SEND_1)
        return 1;

    change_symmetric_key(onion);

    uint8_t plain[ONION_MAX_PACKET_SIZE];
    uint8_t shared_key[crypto_box_BEFORENMBYTES];
    get_shared_key(&onion->shared_keys_1, shared_key, onion->dht->self_secret_key, packet + 1 + crypto_box_NONCEBYTES);
    int len = decrypt_data_symmetric(shared_key, packet + 1, packet + 1 + crypto_box_NONCEBYTES + crypto_box_PUBLICKEYBYTES,
                                     length - (1 + crypto_box_NONCEBYTES + crypto_box_PUBLICKEYBYTES), plain);

    if ((uint32_t)len != length - (1 + crypto_box_NONCEBYTES + crypto_box_PUBLICKEYBYTES + crypto_box_MACBYTES))
        return 1;

    return onion_send_1(onion, plain, len, source, packet + 1);
}

int onion_send_1(const Onion *onion, const uint8_t *plain, uint32_t len, IP_Port source, const uint8_t *nonce)
{
    IP_Port send_to;
    ipport_unpack(&send_to, plain);
    to_host_family(&send_to.ip);

    uint8_t ip_port[SIZE_IPPORT];
    ipport_pack(ip_port, &source);

    uint8_t data[ONION_MAX_PACKET_SIZE];
    data[0] = NET_PACKET_ONION_SEND_1;
    memcpy(data + 1, nonce, crypto_box_NONCEBYTES);
    memcpy(data + 1 + crypto_box_NONCEBYTES, plain + SIZE_IPPORT, len - SIZE_IPPORT);
    uint32_t data_len = 1 + crypto_box_NONCEBYTES + (len - SIZE_IPPORT);
    uint8_t *ret_part = data + data_len;
    new_nonce(ret_part);
    len = encrypt_data_symmetric(onion->secret_symmetric_key, ret_part, ip_port, SIZE_IPPORT,
                                 ret_part + crypto_box_NONCEBYTES);

    if (len != SIZE_IPPORT + crypto_box_MACBYTES)
        return 1;

    data_len += crypto_box_NONCEBYTES + len;

    if ((uint32_t)sendpacket(onion->net, send_to, data, data_len) != data_len)
        return 1;

    return 0;
}

static int handle_send_1(void *object, IP_Port source, const uint8_t *packet, uint32_t length)
{
    Onion *onion = object;

    if (length > ONION_MAX_PACKET_SIZE)
        return 1;

    if (length <= 1 + SEND_2)
        return 1;

    change_symmetric_key(onion);

    uint8_t plain[ONION_MAX_PACKET_SIZE];
    uint8_t shared_key[crypto_box_BEFORENMBYTES];
    get_shared_key(&onion->shared_keys_2, shared_key, onion->dht->self_secret_key, packet + 1 + crypto_box_NONCEBYTES);
    int len = decrypt_data_symmetric(shared_key, packet + 1, packet + 1 + crypto_box_NONCEBYTES + crypto_box_PUBLICKEYBYTES,
                                     length - (1 + crypto_box_NONCEBYTES + crypto_box_PUBLICKEYBYTES + RETURN_1), plain);

    if ((uint32_t)len != length - (1 + crypto_box_NONCEBYTES + crypto_box_PUBLICKEYBYTES + RETURN_1 + crypto_box_MACBYTES))
        return 1;

    IP_Port send_to;
    ipport_unpack(&send_to, plain);
    to_host_family(&send_to.ip);

    uint8_t data[ONION_MAX_PACKET_SIZE];
    data[0] = NET_PACKET_ONION_SEND_2;
    memcpy(data + 1, packet + 1, crypto_box_NONCEBYTES);
    memcpy(data + 1 + crypto_box_NONCEBYTES, plain + SIZE_IPPORT, len - SIZE_IPPORT);
    uint32_t data_len = 1 + crypto_box_NONCEBYTES + (len - SIZE_IPPORT);
    uint8_t *ret_part = data + data_len;
    new_nonce(ret_part);
    uint8_t ret_data[RETURN_1 + SIZE_IPPORT];
    ipport_pack(ret_data, &source);
    memcpy(ret_data + SIZE_IPPORT, packet + (length - RETURN_1), RETURN_1);
    len = encrypt_data_symmetric(onion->secret_symmetric_key, ret_part, ret_data, sizeof(ret_data),
                                 ret_part + crypto_box_NONCEBYTES);

    if (len != RETURN_2 - crypto_box_NONCEBYTES)
        return 1;

    data_len += crypto_box_NONCEBYTES + len;

    if ((uint32_t)sendpacket(onion->net, send_to, data, data_len) != data_len)
        return 1;

    return 0;
}

static int handle_send_2(void *object, IP_Port source, const uint8_t *packet, uint32_t length)
{
    Onion *onion = object;

    if (length > ONION_MAX_PACKET_SIZE)
        return 1;

    if (length <= 1 + SEND_3)
        return 1;

    change_symmetric_key(onion);

    uint8_t plain[ONION_MAX_PACKET_SIZE];
    uint8_t shared_key[crypto_box_BEFORENMBYTES];
    get_shared_key(&onion->shared_keys_3, shared_key, onion->dht->self_secret_key, packet + 1 + crypto_box_NONCEBYTES);
    int len = decrypt_data_symmetric(shared_key, packet + 1, packet + 1 + crypto_box_NONCEBYTES + crypto_box_PUBLICKEYBYTES,
                                     length - (1 + crypto_box_NONCEBYTES + crypto_box_PUBLICKEYBYTES + RETURN_2), plain);

    if ((uint32_t)len != length - (1 + crypto_box_NONCEBYTES + crypto_box_PUBLICKEYBYTES + RETURN_2 + crypto_box_MACBYTES))
        return 1;

    IP_Port send_to;
    ipport_unpack(&send_to, plain);
    to_host_family(&send_to.ip);

    uint8_t data[ONION_MAX_PACKET_SIZE];
    memcpy(data, plain + SIZE_IPPORT, len - SIZE_IPPORT);
    uint32_t data_len = (len - SIZE_IPPORT);
    uint8_t *ret_part = data + (len - SIZE_IPPORT);
    new_nonce(ret_part);
    uint8_t ret_data[RETURN_2 + SIZE_IPPORT];
    ipport_pack(ret_data, &source);
    memcpy(ret_data + SIZE_IPPORT, packet + (length - RETURN_2), RETURN_2);
    len = encrypt_data_symmetric(onion->secret_symmetric_key, ret_part, ret_data, sizeof(ret_data),
                                 ret_part + crypto_box_NONCEBYTES);

    if (len != RETURN_3 - crypto_box_NONCEBYTES)
        return 1;

    data_len += RETURN_3;

    if ((uint32_t)sendpacket(onion->net, send_to, data, data_len) != data_len)
        return 1;

    return 0;
}


static int handle_recv_3(void *object, IP_Port source, const uint8_t *packet, uint32_t length)
{
    Onion *onion = object;

    if (length > ONION_MAX_PACKET_SIZE)
        return 1;

    if (length <= 1 + RETURN_3)
        return 1;

    change_symmetric_key(onion);

    uint8_t plain[SIZE_IPPORT + RETURN_2];
    int len = decrypt_data_symmetric(onion->secret_symmetric_key, packet + 1, packet + 1 + crypto_box_NONCEBYTES,
                                     SIZE_IPPORT + RETURN_2 + crypto_box_MACBYTES, plain);

    if ((uint32_t)len != sizeof(plain))
        return 1;

    IP_Port send_to;
    ipport_unpack(&send_to, plain);

    uint8_t data[ONION_MAX_PACKET_SIZE];
    data[0] = NET_PACKET_ONION_RECV_2;
    memcpy(data + 1, plain + SIZE_IPPORT, RETURN_2);
    memcpy(data + 1 + RETURN_2, packet + 1 + RETURN_3, length - (1 + RETURN_3));
    uint32_t data_len = 1 + RETURN_2 + (length - (1 + RETURN_3));

    if ((uint32_t)sendpacket(onion->net, send_to, data, data_len) != data_len)
        return 1;

    return 0;
}

static int handle_recv_2(void *object, IP_Port source, const uint8_t *packet, uint32_t length)
{
    Onion *onion = object;

    if (length > ONION_MAX_PACKET_SIZE)
        return 1;

    if (length <= 1 + RETURN_2)
        return 1;

    change_symmetric_key(onion);

    uint8_t plain[SIZE_IPPORT + RETURN_1];
    int len = decrypt_data_symmetric(onion->secret_symmetric_key, packet + 1, packet + 1 + crypto_box_NONCEBYTES,
                                     SIZE_IPPORT + RETURN_1 + crypto_box_MACBYTES, plain);

    if ((uint32_t)len != sizeof(plain))
        return 1;

    IP_Port send_to;
    ipport_unpack(&send_to, plain);

    uint8_t data[ONION_MAX_PACKET_SIZE];
    data[0] = NET_PACKET_ONION_RECV_1;
    memcpy(data + 1, plain + SIZE_IPPORT, RETURN_1);
    memcpy(data + 1 + RETURN_1, packet + 1 + RETURN_2, length - (1 + RETURN_2));
    uint32_t data_len = 1 + RETURN_1 + (length - (1 + RETURN_2));

    if ((uint32_t)sendpacket(onion->net, send_to, data, data_len) != data_len)
        return 1;

    return 0;
}

static int handle_recv_1(void *object, IP_Port source, const uint8_t *packet, uint32_t length)
{
    Onion *onion = object;

    if (length > ONION_MAX_PACKET_SIZE)
        return 1;

    if (length <= 1 + RETURN_1)
        return 1;

    change_symmetric_key(onion);

    uint8_t plain[SIZE_IPPORT];
    int len = decrypt_data_symmetric(onion->secret_symmetric_key, packet + 1, packet + 1 + crypto_box_NONCEBYTES,
                                     SIZE_IPPORT + crypto_box_MACBYTES, plain);

    if ((uint32_t)len != SIZE_IPPORT)
        return 1;

    IP_Port send_to;
    ipport_unpack(&send_to, plain);

    uint32_t data_len = length - (1 + RETURN_1);

    if (onion->recv_1_function && send_to.ip.family != AF_INET && send_to.ip.family != AF_INET6)
        return onion->recv_1_function(onion->callback_object, send_to, packet + (1 + RETURN_1), data_len);

    if ((uint32_t)sendpacket(onion->net, send_to, packet + (1 + RETURN_1), data_len) != data_len)
        return 1;

    return 0;
}

void set_callback_handle_recv_1(Onion *onion, int (*function)(void *, IP_Port, const uint8_t *, uint16_t), void *object)
{
    onion->recv_1_function = function;
    onion->callback_object = object;
}

Onion *new_onion(DHT *dht)
{
    if (dht == NULL)
        return NULL;

    Onion *onion = calloc(1, sizeof(Onion));

    if (onion == NULL)
        return NULL;

    onion->dht = dht;
    onion->net = dht->net;
    new_symmetric_key(onion->secret_symmetric_key);
    onion->timestamp = unix_time();

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
