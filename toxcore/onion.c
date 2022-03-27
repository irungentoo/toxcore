/* SPDX-License-Identifier: GPL-3.0-or-later
 * Copyright © 2016-2018 The TokTok team.
 * Copyright © 2013 Tox project.
 */

/**
 * Implementation of the onion part of docs/Prevent_Tracking.txt
 */
#include "onion.h"

#include <assert.h>
#include <stdlib.h>
#include <string.h>

#include "ccompat.h"
#include "mono_time.h"
#include "util.h"

#define RETURN_1 ONION_RETURN_1
#define RETURN_2 ONION_RETURN_2
#define RETURN_3 ONION_RETURN_3

#define SEND_BASE ONION_SEND_BASE
#define SEND_3 ONION_SEND_3
#define SEND_2 ONION_SEND_2
#define SEND_1 ONION_SEND_1

#define KEY_REFRESH_INTERVAL (2 * 60 * 60)

/** Change symmetric keys every 2 hours to make paths expire eventually. */
non_null()
static void change_symmetric_key(Onion *onion)
{
    if (mono_time_is_timeout(onion->mono_time, onion->timestamp, KEY_REFRESH_INTERVAL)) {
        new_symmetric_key(onion->rng, onion->secret_symmetric_key);
        onion->timestamp = mono_time_get(onion->mono_time);
    }
}

/** packing and unpacking functions */
non_null()
static void ip_pack(uint8_t *data, const IP *source)
{
    data[0] = source->family.value;

    if (net_family_is_ipv4(source->family) || net_family_is_tox_tcp_ipv4(source->family)) {
        memset(data + 1, 0, SIZE_IP6);
        memcpy(data + 1, source->ip.v4.uint8, SIZE_IP4);
    } else {
        memcpy(data + 1, source->ip.v6.uint8, SIZE_IP6);
    }
}

/** return 0 on success, -1 on failure. */
non_null()
static int ip_unpack(IP *target, const uint8_t *data, unsigned int data_size, bool disable_family_check)
{
    if (data_size < (1 + SIZE_IP6)) {
        return -1;
    }

    // TODO(iphydf): Validate input.
    target->family.value = data[0];

    if (net_family_is_ipv4(target->family) || net_family_is_tox_tcp_ipv4(target->family)) {
        memcpy(target->ip.v4.uint8, data + 1, SIZE_IP4);
    } else {
        memcpy(target->ip.v6.uint8, data + 1, SIZE_IP6);
    }

    const bool valid = disable_family_check ||
                 net_family_is_ipv4(target->family) ||
                 net_family_is_ipv6(target->family);

    return valid ? 0 : -1;
}

non_null()
static void ipport_pack(uint8_t *data, const IP_Port *source)
{
    ip_pack(data, &source->ip);
    memcpy(data + SIZE_IP, &source->port, SIZE_PORT);
}

/** return 0 on success, -1 on failure. */
non_null()
static int ipport_unpack(IP_Port *target, const uint8_t *data, unsigned int data_size, bool disable_family_check)
{
    if (data_size < (SIZE_IP + SIZE_PORT)) {
        return -1;
    }

    if (ip_unpack(&target->ip, data, data_size, disable_family_check) == -1) {
        return -1;
    }

    memcpy(&target->port, data + SIZE_IP, SIZE_PORT);
    return 0;
}


/** @brief Create a new onion path.
 *
 * Create a new onion path out of nodes (nodes is a list of ONION_PATH_LENGTH nodes)
 *
 * new_path must be an empty memory location of at least Onion_Path size.
 *
 * return -1 on failure.
 * return 0 on success.
 */
int create_onion_path(const Random *rng, const DHT *dht, Onion_Path *new_path, const Node_format *nodes)
{
    if (new_path == nullptr || nodes == nullptr) {
        return -1;
    }

    encrypt_precompute(nodes[0].public_key, dht_get_self_secret_key(dht), new_path->shared_key1);
    memcpy(new_path->public_key1, dht_get_self_public_key(dht), CRYPTO_PUBLIC_KEY_SIZE);

    uint8_t random_public_key[CRYPTO_PUBLIC_KEY_SIZE];
    uint8_t random_secret_key[CRYPTO_SECRET_KEY_SIZE];

    crypto_new_keypair(rng, random_public_key, random_secret_key);
    encrypt_precompute(nodes[1].public_key, random_secret_key, new_path->shared_key2);
    memcpy(new_path->public_key2, random_public_key, CRYPTO_PUBLIC_KEY_SIZE);

    crypto_new_keypair(rng, random_public_key, random_secret_key);
    encrypt_precompute(nodes[2].public_key, random_secret_key, new_path->shared_key3);
    memcpy(new_path->public_key3, random_public_key, CRYPTO_PUBLIC_KEY_SIZE);

    crypto_memzero(random_secret_key, sizeof(random_secret_key));

    new_path->ip_port1 = nodes[0].ip_port;
    new_path->ip_port2 = nodes[1].ip_port;
    new_path->ip_port3 = nodes[2].ip_port;

    memcpy(new_path->node_public_key1, nodes[0].public_key, CRYPTO_PUBLIC_KEY_SIZE);
    memcpy(new_path->node_public_key2, nodes[1].public_key, CRYPTO_PUBLIC_KEY_SIZE);
    memcpy(new_path->node_public_key3, nodes[2].public_key, CRYPTO_PUBLIC_KEY_SIZE);

    return 0;
}

/** @brief Dump nodes in onion path to nodes of length num_nodes.
 *
 * return -1 on failure.
 * return 0 on success.
 */
int onion_path_to_nodes(Node_format *nodes, unsigned int num_nodes, const Onion_Path *path)
{
    if (num_nodes < ONION_PATH_LENGTH) {
        return -1;
    }

    nodes[0].ip_port = path->ip_port1;
    nodes[1].ip_port = path->ip_port2;
    nodes[2].ip_port = path->ip_port3;

    memcpy(nodes[0].public_key, path->node_public_key1, CRYPTO_PUBLIC_KEY_SIZE);
    memcpy(nodes[1].public_key, path->node_public_key2, CRYPTO_PUBLIC_KEY_SIZE);
    memcpy(nodes[2].public_key, path->node_public_key3, CRYPTO_PUBLIC_KEY_SIZE);
    return 0;
}

/** @brief Create a onion packet.
 *
 * Use Onion_Path path to create packet for data of length to dest.
 * Maximum length of data is ONION_MAX_DATA_SIZE.
 * packet should be at least ONION_MAX_PACKET_SIZE big.
 *
 * return -1 on failure.
 * return length of created packet on success.
 */
int create_onion_packet(const Random *rng, uint8_t *packet, uint16_t max_packet_length,
                        const Onion_Path *path, const IP_Port *dest,
                        const uint8_t *data, uint16_t length)
{
    if (1 + length + SEND_1 > max_packet_length || length == 0) {
        return -1;
    }

    VLA(uint8_t, step1, SIZE_IPPORT + length);

    ipport_pack(step1, dest);
    memcpy(step1 + SIZE_IPPORT, data, length);

    uint8_t nonce[CRYPTO_NONCE_SIZE];
    random_nonce(rng, nonce);

    VLA(uint8_t, step2, SIZE_IPPORT + SEND_BASE + length);
    ipport_pack(step2, &path->ip_port3);
    memcpy(step2 + SIZE_IPPORT, path->public_key3, CRYPTO_PUBLIC_KEY_SIZE);

    int len = encrypt_data_symmetric(path->shared_key3, nonce, step1, SIZEOF_VLA(step1),
                                     step2 + SIZE_IPPORT + CRYPTO_PUBLIC_KEY_SIZE);

    if (len != SIZE_IPPORT + length + CRYPTO_MAC_SIZE) {
        return -1;
    }

    VLA(uint8_t, step3, SIZE_IPPORT + SEND_BASE * 2 + length);
    ipport_pack(step3, &path->ip_port2);
    memcpy(step3 + SIZE_IPPORT, path->public_key2, CRYPTO_PUBLIC_KEY_SIZE);
    len = encrypt_data_symmetric(path->shared_key2, nonce, step2, SIZEOF_VLA(step2),
                                 step3 + SIZE_IPPORT + CRYPTO_PUBLIC_KEY_SIZE);

    if (len != SIZE_IPPORT + SEND_BASE + length + CRYPTO_MAC_SIZE) {
        return -1;
    }

    packet[0] = NET_PACKET_ONION_SEND_INITIAL;
    memcpy(packet + 1, nonce, CRYPTO_NONCE_SIZE);
    memcpy(packet + 1 + CRYPTO_NONCE_SIZE, path->public_key1, CRYPTO_PUBLIC_KEY_SIZE);

    len = encrypt_data_symmetric(path->shared_key1, nonce, step3, SIZEOF_VLA(step3),
                                 packet + 1 + CRYPTO_NONCE_SIZE + CRYPTO_PUBLIC_KEY_SIZE);

    if (len != SIZE_IPPORT + SEND_BASE * 2 + length + CRYPTO_MAC_SIZE) {
        return -1;
    }

    return 1 + CRYPTO_NONCE_SIZE + CRYPTO_PUBLIC_KEY_SIZE + len;
}

/** @brief Create a onion packet to be sent over tcp.
 *
 * Use Onion_Path path to create packet for data of length to dest.
 * Maximum length of data is ONION_MAX_DATA_SIZE.
 * packet should be at least ONION_MAX_PACKET_SIZE big.
 *
 * return -1 on failure.
 * return length of created packet on success.
 */
int create_onion_packet_tcp(const Random *rng, uint8_t *packet, uint16_t max_packet_length,
                            const Onion_Path *path, const IP_Port *dest,
                            const uint8_t *data, uint16_t length)
{
    if (CRYPTO_NONCE_SIZE + SIZE_IPPORT + SEND_BASE * 2 + length > max_packet_length || length == 0) {
        return -1;
    }

    VLA(uint8_t, step1, SIZE_IPPORT + length);

    ipport_pack(step1, dest);
    memcpy(step1 + SIZE_IPPORT, data, length);

    uint8_t nonce[CRYPTO_NONCE_SIZE];
    random_nonce(rng, nonce);

    VLA(uint8_t, step2, SIZE_IPPORT + SEND_BASE + length);
    ipport_pack(step2, &path->ip_port3);
    memcpy(step2 + SIZE_IPPORT, path->public_key3, CRYPTO_PUBLIC_KEY_SIZE);

    int len = encrypt_data_symmetric(path->shared_key3, nonce, step1, SIZEOF_VLA(step1),
                                     step2 + SIZE_IPPORT + CRYPTO_PUBLIC_KEY_SIZE);

    if (len != SIZE_IPPORT + length + CRYPTO_MAC_SIZE) {
        return -1;
    }

    ipport_pack(packet + CRYPTO_NONCE_SIZE, &path->ip_port2);
    memcpy(packet + CRYPTO_NONCE_SIZE + SIZE_IPPORT, path->public_key2, CRYPTO_PUBLIC_KEY_SIZE);
    len = encrypt_data_symmetric(path->shared_key2, nonce, step2, SIZEOF_VLA(step2),
                                 packet + CRYPTO_NONCE_SIZE + SIZE_IPPORT + CRYPTO_PUBLIC_KEY_SIZE);

    if (len != SIZE_IPPORT + SEND_BASE + length + CRYPTO_MAC_SIZE) {
        return -1;
    }

    memcpy(packet, nonce, CRYPTO_NONCE_SIZE);

    return CRYPTO_NONCE_SIZE + SIZE_IPPORT + CRYPTO_PUBLIC_KEY_SIZE + len;
}

/** @brief Create and send a onion response sent initially to dest with.
 * Maximum length of data is ONION_RESPONSE_MAX_DATA_SIZE.
 *
 * return -1 on failure.
 * return 0 on success.
 */
int send_onion_response(const Networking_Core *net, const IP_Port *dest, const uint8_t *data, uint16_t length,
                        const uint8_t *ret)
{
    if (length > ONION_RESPONSE_MAX_DATA_SIZE || length == 0) {
        return -1;
    }

    VLA(uint8_t, packet, 1 + RETURN_3 + length);
    packet[0] = NET_PACKET_ONION_RECV_3;
    memcpy(packet + 1, ret, RETURN_3);
    memcpy(packet + 1 + RETURN_3, data, length);

    if ((uint32_t)sendpacket(net, dest, packet, SIZEOF_VLA(packet)) != SIZEOF_VLA(packet)) {
        return -1;
    }

    return 0;
}

non_null()
static int handle_send_initial(void *object, const IP_Port *source, const uint8_t *packet, uint16_t length,
                               void *userdata)
{
    Onion *onion = (Onion *)object;

    if (length > ONION_MAX_PACKET_SIZE) {
        return 1;
    }

    if (length <= 1 + SEND_1) {
        return 1;
    }

    change_symmetric_key(onion);

    uint8_t plain[ONION_MAX_PACKET_SIZE];
    uint8_t shared_key[CRYPTO_SHARED_KEY_SIZE];
    get_shared_key(onion->mono_time, &onion->shared_keys_1, shared_key, dht_get_self_secret_key(onion->dht),
                   packet + 1 + CRYPTO_NONCE_SIZE);
    const int len = decrypt_data_symmetric(shared_key, packet + 1, packet + 1 + CRYPTO_NONCE_SIZE + CRYPTO_PUBLIC_KEY_SIZE,
                                     length - (1 + CRYPTO_NONCE_SIZE + CRYPTO_PUBLIC_KEY_SIZE), plain);

    if (len != length - (1 + CRYPTO_NONCE_SIZE + CRYPTO_PUBLIC_KEY_SIZE + CRYPTO_MAC_SIZE)) {
        return 1;
    }

    return onion_send_1(onion, plain, len, source, packet + 1);
}

int onion_send_1(const Onion *onion, const uint8_t *plain, uint16_t len, const IP_Port *source, const uint8_t *nonce)
{
    if (len > ONION_MAX_PACKET_SIZE + SIZE_IPPORT - (1 + CRYPTO_NONCE_SIZE + ONION_RETURN_1)) {
        return 1;
    }

    if (len <= SIZE_IPPORT + SEND_BASE * 2) {
        return 1;
    }

    IP_Port send_to;

    if (ipport_unpack(&send_to, plain, len, false) == -1) {
        return 1;
    }

    uint8_t ip_port[SIZE_IPPORT];
    ipport_pack(ip_port, source);

    uint8_t data[ONION_MAX_PACKET_SIZE] = {0};
    data[0] = NET_PACKET_ONION_SEND_1;
    memcpy(data + 1, nonce, CRYPTO_NONCE_SIZE);
    memcpy(data + 1 + CRYPTO_NONCE_SIZE, plain + SIZE_IPPORT, len - SIZE_IPPORT);
    uint16_t data_len = 1 + CRYPTO_NONCE_SIZE + (len - SIZE_IPPORT);
    uint8_t *ret_part = data + data_len;
    random_nonce(onion->rng, ret_part);
    len = encrypt_data_symmetric(onion->secret_symmetric_key, ret_part, ip_port, SIZE_IPPORT,
                                 ret_part + CRYPTO_NONCE_SIZE);

    if (len != SIZE_IPPORT + CRYPTO_MAC_SIZE) {
        return 1;
    }

    data_len += CRYPTO_NONCE_SIZE + len;

    if ((uint32_t)sendpacket(onion->net, &send_to, data, data_len) != data_len) {
        return 1;
    }

    return 0;
}

non_null()
static int handle_send_1(void *object, const IP_Port *source, const uint8_t *packet, uint16_t length, void *userdata)
{
    Onion *onion = (Onion *)object;

    if (length > ONION_MAX_PACKET_SIZE) {
        return 1;
    }

    if (length <= 1 + SEND_2) {
        return 1;
    }

    change_symmetric_key(onion);

    uint8_t plain[ONION_MAX_PACKET_SIZE];
    uint8_t shared_key[CRYPTO_SHARED_KEY_SIZE];
    get_shared_key(onion->mono_time, &onion->shared_keys_2, shared_key, dht_get_self_secret_key(onion->dht),
                   packet + 1 + CRYPTO_NONCE_SIZE);
    int len = decrypt_data_symmetric(shared_key, packet + 1, packet + 1 + CRYPTO_NONCE_SIZE + CRYPTO_PUBLIC_KEY_SIZE,
                                     length - (1 + CRYPTO_NONCE_SIZE + CRYPTO_PUBLIC_KEY_SIZE + RETURN_1), plain);

    if (len != length - (1 + CRYPTO_NONCE_SIZE + CRYPTO_PUBLIC_KEY_SIZE + RETURN_1 + CRYPTO_MAC_SIZE)) {
        return 1;
    }

    IP_Port send_to;

    if (ipport_unpack(&send_to, plain, len, false) == -1) {
        return 1;
    }

    uint8_t data[ONION_MAX_PACKET_SIZE] = {0};
    data[0] = NET_PACKET_ONION_SEND_2;
    memcpy(data + 1, packet + 1, CRYPTO_NONCE_SIZE);
    memcpy(data + 1 + CRYPTO_NONCE_SIZE, plain + SIZE_IPPORT, len - SIZE_IPPORT);
    uint16_t data_len = 1 + CRYPTO_NONCE_SIZE + (len - SIZE_IPPORT);
    uint8_t *ret_part = data + data_len;
    random_nonce(onion->rng, ret_part);
    uint8_t ret_data[RETURN_1 + SIZE_IPPORT];
    ipport_pack(ret_data, source);
    memcpy(ret_data + SIZE_IPPORT, packet + (length - RETURN_1), RETURN_1);
    len = encrypt_data_symmetric(onion->secret_symmetric_key, ret_part, ret_data, sizeof(ret_data),
                                 ret_part + CRYPTO_NONCE_SIZE);

    if (len != RETURN_2 - CRYPTO_NONCE_SIZE) {
        return 1;
    }

    data_len += CRYPTO_NONCE_SIZE + len;

    if ((uint32_t)sendpacket(onion->net, &send_to, data, data_len) != data_len) {
        return 1;
    }

    return 0;
}

non_null()
static int handle_send_2(void *object, const IP_Port *source, const uint8_t *packet, uint16_t length, void *userdata)
{
    Onion *onion = (Onion *)object;

    if (length > ONION_MAX_PACKET_SIZE) {
        return 1;
    }

    if (length <= 1 + SEND_3) {
        return 1;
    }

    change_symmetric_key(onion);

    uint8_t plain[ONION_MAX_PACKET_SIZE];
    uint8_t shared_key[CRYPTO_SHARED_KEY_SIZE];
    get_shared_key(onion->mono_time, &onion->shared_keys_3, shared_key, dht_get_self_secret_key(onion->dht),
                   packet + 1 + CRYPTO_NONCE_SIZE);
    int len = decrypt_data_symmetric(shared_key, packet + 1, packet + 1 + CRYPTO_NONCE_SIZE + CRYPTO_PUBLIC_KEY_SIZE,
                                     length - (1 + CRYPTO_NONCE_SIZE + CRYPTO_PUBLIC_KEY_SIZE + RETURN_2), plain);

    if (len != length - (1 + CRYPTO_NONCE_SIZE + CRYPTO_PUBLIC_KEY_SIZE + RETURN_2 + CRYPTO_MAC_SIZE)) {
        return 1;
    }

    assert(len > SIZE_IPPORT);

    const uint8_t packet_id = plain[SIZE_IPPORT];

    if (packet_id != NET_PACKET_ANNOUNCE_REQUEST_OLD && packet_id != NET_PACKET_ONION_DATA_REQUEST) {
        return 1;
    }

    IP_Port send_to;

    if (ipport_unpack(&send_to, plain, len, false) == -1) {
        return 1;
    }

    uint8_t data[ONION_MAX_PACKET_SIZE] = {0};
    memcpy(data, plain + SIZE_IPPORT, len - SIZE_IPPORT);
    uint16_t data_len = len - SIZE_IPPORT;
    uint8_t *ret_part = data + (len - SIZE_IPPORT);
    random_nonce(onion->rng, ret_part);
    uint8_t ret_data[RETURN_2 + SIZE_IPPORT];
    ipport_pack(ret_data, source);
    memcpy(ret_data + SIZE_IPPORT, packet + (length - RETURN_2), RETURN_2);
    len = encrypt_data_symmetric(onion->secret_symmetric_key, ret_part, ret_data, sizeof(ret_data),
                                 ret_part + CRYPTO_NONCE_SIZE);

    if (len != RETURN_3 - CRYPTO_NONCE_SIZE) {
        return 1;
    }

    data_len += RETURN_3;

    if ((uint32_t)sendpacket(onion->net, &send_to, data, data_len) != data_len) {
        return 1;
    }

    return 0;
}


non_null()
static int handle_recv_3(void *object, const IP_Port *source, const uint8_t *packet, uint16_t length, void *userdata)
{
    Onion *onion = (Onion *)object;

    if (length > ONION_MAX_PACKET_SIZE) {
        return 1;
    }

    if (length <= 1 + RETURN_3) {
        return 1;
    }

    const uint8_t packet_id = packet[1 + RETURN_3];

    if (packet_id != NET_PACKET_ANNOUNCE_RESPONSE_OLD && packet_id != NET_PACKET_ONION_DATA_RESPONSE) {
        return 1;
    }

    change_symmetric_key(onion);

    uint8_t plain[SIZE_IPPORT + RETURN_2];
    const int len = decrypt_data_symmetric(onion->secret_symmetric_key, packet + 1, packet + 1 + CRYPTO_NONCE_SIZE,
                                     SIZE_IPPORT + RETURN_2 + CRYPTO_MAC_SIZE, plain);

    if ((uint32_t)len != sizeof(plain)) {
        return 1;
    }

    IP_Port send_to;

    if (ipport_unpack(&send_to, plain, len, false) == -1) {
        return 1;
    }

    uint8_t data[ONION_MAX_PACKET_SIZE] = {0};
    data[0] = NET_PACKET_ONION_RECV_2;
    memcpy(data + 1, plain + SIZE_IPPORT, RETURN_2);
    memcpy(data + 1 + RETURN_2, packet + 1 + RETURN_3, length - (1 + RETURN_3));
    const uint16_t data_len = 1 + RETURN_2 + (length - (1 + RETURN_3));

    if ((uint32_t)sendpacket(onion->net, &send_to, data, data_len) != data_len) {
        return 1;
    }

    return 0;
}

non_null()
static int handle_recv_2(void *object, const IP_Port *source, const uint8_t *packet, uint16_t length, void *userdata)
{
    Onion *onion = (Onion *)object;

    if (length > ONION_MAX_PACKET_SIZE) {
        return 1;
    }

    if (length <= 1 + RETURN_2) {
        return 1;
    }

    const uint8_t packet_id = packet[1 + RETURN_2];

    if (packet_id != NET_PACKET_ANNOUNCE_RESPONSE_OLD && packet_id != NET_PACKET_ONION_DATA_RESPONSE) {
        return 1;
    }

    change_symmetric_key(onion);

    uint8_t plain[SIZE_IPPORT + RETURN_1];
    const int len = decrypt_data_symmetric(onion->secret_symmetric_key, packet + 1, packet + 1 + CRYPTO_NONCE_SIZE,
                                     SIZE_IPPORT + RETURN_1 + CRYPTO_MAC_SIZE, plain);

    if ((uint32_t)len != sizeof(plain)) {
        return 1;
    }

    IP_Port send_to;

    if (ipport_unpack(&send_to, plain, len, false) == -1) {
        return 1;
    }

    uint8_t data[ONION_MAX_PACKET_SIZE] = {0};
    data[0] = NET_PACKET_ONION_RECV_1;
    memcpy(data + 1, plain + SIZE_IPPORT, RETURN_1);
    memcpy(data + 1 + RETURN_1, packet + 1 + RETURN_2, length - (1 + RETURN_2));
    const uint16_t data_len = 1 + RETURN_1 + (length - (1 + RETURN_2));

    if ((uint32_t)sendpacket(onion->net, &send_to, data, data_len) != data_len) {
        return 1;
    }

    return 0;
}

non_null()
static int handle_recv_1(void *object, const IP_Port *source, const uint8_t *packet, uint16_t length, void *userdata)
{
    Onion *onion = (Onion *)object;

    if (length > ONION_MAX_PACKET_SIZE) {
        return 1;
    }

    if (length <= 1 + RETURN_1) {
        return 1;
    }

    const uint8_t packet_id = packet[1 + RETURN_1];

    if (packet_id != NET_PACKET_ANNOUNCE_RESPONSE_OLD && packet_id != NET_PACKET_ONION_DATA_RESPONSE) {
        return 1;
    }

    change_symmetric_key(onion);

    uint8_t plain[SIZE_IPPORT];
    const int len = decrypt_data_symmetric(onion->secret_symmetric_key, packet + 1, packet + 1 + CRYPTO_NONCE_SIZE,
                                     SIZE_IPPORT + CRYPTO_MAC_SIZE, plain);

    if ((uint32_t)len != SIZE_IPPORT) {
        return 1;
    }

    IP_Port send_to;

    if (ipport_unpack(&send_to, plain, len, true) == -1) {
        return 1;
    }

    const uint16_t data_len = length - (1 + RETURN_1);

    if (onion->recv_1_function != nullptr &&
            !net_family_is_ipv4(send_to.ip.family) &&
            !net_family_is_ipv6(send_to.ip.family)) {
        return onion->recv_1_function(onion->callback_object, &send_to, packet + (1 + RETURN_1), data_len);
    }

    if ((uint32_t)sendpacket(onion->net, &send_to, packet + (1 + RETURN_1), data_len) != data_len) {
        return 1;
    }

    return 0;
}

void set_callback_handle_recv_1(Onion *onion, onion_recv_1_cb *function, void *object)
{
    onion->recv_1_function = function;
    onion->callback_object = object;
}

Onion *new_onion(const Logger *log, const Mono_Time *mono_time, const Random *rng, DHT *dht)
{
    if (dht == nullptr) {
        return nullptr;
    }

    Onion *onion = (Onion *)calloc(1, sizeof(Onion));

    if (onion == nullptr) {
        return nullptr;
    }

    onion->log = log;
    onion->dht = dht;
    onion->net = dht_get_net(dht);
    onion->mono_time = mono_time;
    onion->rng = rng;
    new_symmetric_key(rng, onion->secret_symmetric_key);
    onion->timestamp = mono_time_get(onion->mono_time);

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
    if (onion == nullptr) {
        return;
    }

    networking_registerhandler(onion->net, NET_PACKET_ONION_SEND_INITIAL, nullptr, nullptr);
    networking_registerhandler(onion->net, NET_PACKET_ONION_SEND_1, nullptr, nullptr);
    networking_registerhandler(onion->net, NET_PACKET_ONION_SEND_2, nullptr, nullptr);

    networking_registerhandler(onion->net, NET_PACKET_ONION_RECV_3, nullptr, nullptr);
    networking_registerhandler(onion->net, NET_PACKET_ONION_RECV_2, nullptr, nullptr);
    networking_registerhandler(onion->net, NET_PACKET_ONION_RECV_1, nullptr, nullptr);

    crypto_memzero(onion->secret_symmetric_key, sizeof(onion->secret_symmetric_key));

    free(onion);
}
