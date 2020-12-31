/* SPDX-License-Identifier: GPL-3.0-or-later
 * Copyright © 2019-2022 The TokTok team.
 */

#include "forwarding.h"

#include <assert.h>
#include <stdlib.h>
#include <string.h>

#include "DHT.h"
#include "ccompat.h"
#include "timed_auth.h"

struct Forwarding {
    const Logger *log;
    const Random *rng;
    DHT *dht;
    const Mono_Time *mono_time;
    Networking_Core *net;

    uint8_t hmac_key[CRYPTO_HMAC_KEY_SIZE];

    forward_reply_cb *forward_reply_callback;
    void *forward_reply_callback_object;

    forwarded_request_cb *forwarded_request_callback;
    void *forwarded_request_callback_object;

    forwarded_response_cb *forwarded_response_callback;
    void *forwarded_response_callback_object;
};

DHT *forwarding_get_dht(Forwarding *forwarding)
{
    return forwarding->dht;
}

#define SENDBACK_TIMEOUT 3600

bool send_forward_request(Networking_Core *net, const IP_Port *forwarder,
                          const uint8_t *chain_keys, uint16_t chain_length,
                          const uint8_t *data, uint16_t data_length)
{
    if (chain_length == 0 || chain_length > MAX_FORWARD_CHAIN_LENGTH
            || data_length > MAX_FORWARD_DATA_SIZE) {
        return false;
    }

    const uint16_t len = forward_chain_packet_size(chain_length, data_length);
    VLA(uint8_t, packet, len);

    return create_forward_chain_packet(chain_keys, chain_length, data, data_length, packet)
           && sendpacket(net, forwarder, packet, len) == len;
}

uint16_t forward_chain_packet_size(uint16_t chain_length, uint16_t data_length)
{
    return chain_length * (1 + CRYPTO_PUBLIC_KEY_SIZE) + data_length;
}

bool create_forward_chain_packet(const uint8_t *chain_keys, uint16_t chain_length,
                                 const uint8_t *data, uint16_t data_length,
                                 uint8_t *packet)
{
    if (chain_length == 0 || chain_length > MAX_FORWARD_CHAIN_LENGTH
            || data_length > MAX_FORWARD_DATA_SIZE) {
        return false;
    }

    uint16_t offset = 0;

    for (uint16_t j = 0; j < chain_length; ++j) {
        packet[offset] = NET_PACKET_FORWARD_REQUEST;
        ++offset;
        memcpy(packet + offset, chain_keys + j * CRYPTO_PUBLIC_KEY_SIZE, CRYPTO_PUBLIC_KEY_SIZE);
        offset += CRYPTO_PUBLIC_KEY_SIZE;
    }

    memcpy(packet + offset, data, data_length);
    return true;
}

non_null()
static uint16_t forwarding_packet_length(uint16_t sendback_data_len, uint16_t data_length)
{
    const uint16_t sendback_len = sendback_data_len == 0 ? 0 : TIMED_AUTH_SIZE + sendback_data_len;
    return 1 + 1 + sendback_len + data_length;
}

non_null(1, 4, 6) nullable(2)
static bool create_forwarding_packet(const Forwarding *forwarding,
                                     const uint8_t *sendback_data, uint16_t sendback_data_len,
                                     const uint8_t *data, uint16_t length,
                                     uint8_t *packet)
{
    packet[0] = NET_PACKET_FORWARDING;

    if (sendback_data_len == 0) {
        packet[1] = 0;
        memcpy(packet + 1 + 1, data, length);
    } else {
        const uint16_t sendback_len = TIMED_AUTH_SIZE + sendback_data_len;

        if (sendback_len > MAX_SENDBACK_SIZE) {
            return false;
        }

        packet[1] = sendback_len;
        generate_timed_auth(forwarding->mono_time, SENDBACK_TIMEOUT, forwarding->hmac_key, sendback_data,
                            sendback_data_len, packet + 1 + 1);

        if (sendback_data_len != 0) {
            assert(sendback_data != nullptr);
            memcpy(packet + 1 + 1 + TIMED_AUTH_SIZE, sendback_data, sendback_data_len);
        }

        memcpy(packet + 1 + 1 + sendback_len, data, length);
    }

    return true;
}

bool send_forwarding(const Forwarding *forwarding, const IP_Port *dest,
                     const uint8_t *sendback_data, uint16_t sendback_data_len,
                     const uint8_t *data, uint16_t length)
{
    if (length > MAX_FORWARD_DATA_SIZE) {
        return false;
    }

    const uint16_t len = forwarding_packet_length(sendback_data_len, length);
    VLA(uint8_t, packet, len);
    create_forwarding_packet(forwarding, sendback_data, sendback_data_len, data, length, packet);
    return sendpacket(forwarding->net, dest, packet, len) == len;
}

#define FORWARD_REQUEST_MIN_PACKET_SIZE (1 + CRYPTO_PUBLIC_KEY_SIZE)

non_null(1) nullable(2, 4)
static bool handle_forward_request_dht(const Forwarding *forwarding,
                                       const uint8_t *sendback_data, uint16_t sendback_data_len,
                                       const uint8_t *packet, uint16_t length)
{
    if (length < FORWARD_REQUEST_MIN_PACKET_SIZE) {
        return false;
    }

    const uint8_t *const public_key = packet + 1;
    const uint8_t *const forward_data = packet + (1 + CRYPTO_PUBLIC_KEY_SIZE);
    const uint16_t forward_data_len = length - (1 + CRYPTO_PUBLIC_KEY_SIZE);

    if (TIMED_AUTH_SIZE + sendback_data_len > MAX_SENDBACK_SIZE ||
            forward_data_len > MAX_FORWARD_DATA_SIZE) {
        return false;
    }

    const uint16_t len = forwarding_packet_length(sendback_data_len, forward_data_len);
    VLA(uint8_t, forwarding_packet, len);

    create_forwarding_packet(forwarding, sendback_data, sendback_data_len, forward_data, forward_data_len,
                             forwarding_packet);

    return route_packet(forwarding->dht, public_key, forwarding_packet, len) == len;
}

non_null(1, 2) nullable(3, 5)
static int handle_forward_request(void *object, const IP_Port *source, const uint8_t *packet, uint16_t length,
                                  void *userdata)
{
    const Forwarding *forwarding = (const Forwarding *)object;

    uint8_t sendback_data[1 + MAX_PACKED_IPPORT_SIZE];
    sendback_data[0] = SENDBACK_IPPORT;

    const int ipport_length = pack_ip_port(forwarding->log, sendback_data + 1, MAX_PACKED_IPPORT_SIZE, source);

    if (ipport_length == -1) {
        return 1;
    }

    return handle_forward_request_dht(forwarding, sendback_data, 1 + ipport_length, packet, length) ? 0 : 1;
}

#define MIN_NONEMPTY_SENDBACK_SIZE TIMED_AUTH_SIZE
#define FORWARD_REPLY_MIN_PACKET_SIZE (1 + 1 + MIN_NONEMPTY_SENDBACK_SIZE)

non_null(1, 2) nullable(3, 5)
static int handle_forward_reply(void *object, const IP_Port *source, const uint8_t *packet, uint16_t length,
                                void *userdata)
{
    const Forwarding *forwarding = (const Forwarding *)object;

    if (length < FORWARD_REPLY_MIN_PACKET_SIZE) {
        return 1;
    }

    const uint8_t sendback_len = packet[1];
    const uint8_t *const sendback_auth = packet + 1 + 1;
    const uint8_t *const sendback_data = sendback_auth + TIMED_AUTH_SIZE;

    if (sendback_len > MAX_SENDBACK_SIZE) {
        /* value 0xff is reserved for possible future expansion */
        return 1;
    }

    if (sendback_len < TIMED_AUTH_SIZE + 1) {
        return 1;
    }

    const uint16_t sendback_data_len = sendback_len - TIMED_AUTH_SIZE;

    if (length < 1 + 1 + sendback_len) {
        return 1;
    }

    const uint8_t *const to_forward = packet + (1 + 1 + sendback_len);
    const uint16_t to_forward_len = length - (1 + 1 + sendback_len);

    if (!check_timed_auth(forwarding->mono_time, SENDBACK_TIMEOUT, forwarding->hmac_key, sendback_data, sendback_data_len,
                          sendback_auth)) {
        return 1;
    }

    if (sendback_data[0] == SENDBACK_IPPORT) {
        IP_Port dest;

        if (unpack_ip_port(&dest, sendback_data + 1, sendback_data_len - 1, false)
                != sendback_data_len - 1) {
            return 1;
        }

        return send_forwarding(forwarding, &dest, nullptr, 0, to_forward, to_forward_len) ? 0 : 1;
    }

    if (sendback_data[0] == SENDBACK_FORWARD) {
        IP_Port forwarder;
        const int ipport_length = unpack_ip_port(&forwarder, sendback_data + 1, sendback_data_len - 1, false);

        if (ipport_length == -1) {
            return 1;
        }

        const uint8_t *const forward_sendback = sendback_data + (1 + ipport_length);
        const uint16_t forward_sendback_len = sendback_data_len - (1 + ipport_length);

        return forward_reply(forwarding->net, &forwarder, forward_sendback, forward_sendback_len, to_forward,
                             to_forward_len) ? 0 : 1;
    }

    if (forwarding->forward_reply_callback == nullptr) {
        return 1;
    }

    return forwarding->forward_reply_callback(forwarding->forward_reply_callback_object,
            sendback_data, sendback_data_len,
            to_forward, to_forward_len) ? 0 : 1;
}

#define FORWARDING_MIN_PACKET_SIZE (1 + 1)

non_null(1, 2) nullable(3, 5)
static int handle_forwarding(void *object, const IP_Port *source, const uint8_t *packet, uint16_t length,
                             void *userdata)
{
    const Forwarding *forwarding = (const Forwarding *)object;

    if (length < FORWARDING_MIN_PACKET_SIZE) {
        return 1;
    }

    const uint8_t sendback_len = packet[1];

    if (length < 1 + 1 + sendback_len) {
        return 1;
    }

    const uint8_t *const sendback = packet + 1 + 1;

    const uint8_t *const forwarded = sendback + sendback_len;
    const uint16_t forwarded_len = length - (1 + 1 + sendback_len);

    if (forwarded_len >= 1 && forwarded[0] == NET_PACKET_FORWARD_REQUEST) {
        VLA(uint8_t, sendback_data, 1 + MAX_PACKED_IPPORT_SIZE + sendback_len);
        sendback_data[0] = SENDBACK_FORWARD;

        const int ipport_length = pack_ip_port(forwarding->log, sendback_data + 1, MAX_PACKED_IPPORT_SIZE, source);

        if (ipport_length == -1) {
            return 1;
        }

        memcpy(sendback_data + 1 + ipport_length, sendback, sendback_len);

        return handle_forward_request_dht(forwarding, sendback_data, 1 + ipport_length + sendback_len, forwarded,
                                          forwarded_len) ? 0 : 1;
    }

    if (sendback_len > 0) {
        if (forwarding->forwarded_request_callback == nullptr) {
            return 1;
        }

        forwarding->forwarded_request_callback(forwarding->forwarded_request_callback_object,
                                               source, sendback, sendback_len,
                                               forwarded, forwarded_len, userdata);
        return 0;
    } else {
        if (forwarding->forwarded_response_callback == nullptr) {
            return 1;
        }

        forwarding->forwarded_response_callback(forwarding->forwarded_response_callback_object,
                                                forwarded, forwarded_len, userdata);
        return 0;
    }
}

bool forward_reply(Networking_Core *net, const IP_Port *forwarder,
                   const uint8_t *sendback, uint16_t sendback_length,
                   const uint8_t *data, uint16_t length)
{
    if (sendback_length > MAX_SENDBACK_SIZE ||
            length > MAX_FORWARD_DATA_SIZE) {
        return false;
    }

    const uint16_t len = 1 + 1 + sendback_length + length;
    VLA(uint8_t, packet, len);
    packet[0] = NET_PACKET_FORWARD_REPLY;
    packet[1] = (uint8_t) sendback_length;
    memcpy(packet + 1 + 1, sendback, sendback_length);
    memcpy(packet + 1 + 1 + sendback_length, data, length);
    return sendpacket(net, forwarder, packet, len) == len;
}

void set_callback_forwarded_request(Forwarding *forwarding, forwarded_request_cb *function, void *object)
{
    forwarding->forwarded_request_callback = function;
    forwarding->forwarded_request_callback_object = object;
}

void set_callback_forwarded_response(Forwarding *forwarding, forwarded_response_cb *function, void *object)
{
    forwarding->forwarded_response_callback = function;
    forwarding->forwarded_response_callback_object = object;
}

void set_callback_forward_reply(Forwarding *forwarding, forward_reply_cb *function, void *object)
{
    forwarding->forward_reply_callback = function;
    forwarding->forward_reply_callback_object = object;
}

Forwarding *new_forwarding(const Logger *log, const Random *rng, const Mono_Time *mono_time, DHT *dht)
{
    if (log == nullptr || mono_time == nullptr || dht == nullptr) {
        return nullptr;
    }

    Forwarding *forwarding = (Forwarding *)calloc(1, sizeof(Forwarding));

    if (forwarding == nullptr) {
        return nullptr;
    }

    forwarding->log = log;
    forwarding->rng = rng;
    forwarding->mono_time = mono_time;
    forwarding->dht = dht;
    forwarding->net = dht_get_net(dht);

    networking_registerhandler(forwarding->net, NET_PACKET_FORWARD_REQUEST, &handle_forward_request, forwarding);
    networking_registerhandler(forwarding->net, NET_PACKET_FORWARD_REPLY, &handle_forward_reply, forwarding);
    networking_registerhandler(forwarding->net, NET_PACKET_FORWARDING, &handle_forwarding, forwarding);

    new_hmac_key(forwarding->rng, forwarding->hmac_key);

    return forwarding;
}

void kill_forwarding(Forwarding *forwarding)
{
    if (forwarding == nullptr) {
        return;
    }

    networking_registerhandler(forwarding->net, NET_PACKET_FORWARD_REQUEST, nullptr, nullptr);
    networking_registerhandler(forwarding->net, NET_PACKET_FORWARD_REPLY, nullptr, nullptr);
    networking_registerhandler(forwarding->net, NET_PACKET_FORWARDING, nullptr, nullptr);

    crypto_memzero(forwarding->hmac_key, CRYPTO_HMAC_KEY_SIZE);

    free(forwarding);
}
