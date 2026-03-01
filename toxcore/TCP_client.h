/* SPDX-License-Identifier: GPL-3.0-or-later
 * Copyright © 2016-2026 The TokTok team.
 * Copyright © 2014 Tox project.
 */

/**
 * Implementation of the TCP relay client part of Tox.
 */
#ifndef C_TOXCORE_TOXCORE_TCP_CLIENT_H
#define C_TOXCORE_TOXCORE_TCP_CLIENT_H

#include <stdint.h>

#include "attributes.h"
#include "crypto_core.h"
#include "forwarding.h"
#include "logger.h"
#include "mem.h"
#include "mono_time.h"
#include "net.h"
#include "net_profile.h"
#include "network.h"
#include "rng.h"

#ifdef __cplusplus
extern "C" {
#endif

#define TCP_CONNECTION_TIMEOUT 10

typedef enum TCP_Proxy_Type {
    TCP_PROXY_NONE,
    TCP_PROXY_HTTP,
    TCP_PROXY_SOCKS5,
} TCP_Proxy_Type;

typedef struct TCP_Proxy_Info {
    IP_Port ip_port;
    uint8_t proxy_type; // a value from TCP_PROXY_TYPE
} TCP_Proxy_Info;

typedef enum TCP_Client_Status {
    TCP_CLIENT_NO_STATUS,
    TCP_CLIENT_PROXY_HTTP_CONNECTING,
    TCP_CLIENT_PROXY_SOCKS5_CONNECTING,
    TCP_CLIENT_PROXY_SOCKS5_UNCONFIRMED,
    TCP_CLIENT_CONNECTING,
    TCP_CLIENT_UNCONFIRMED,
    TCP_CLIENT_CONFIRMED,
    TCP_CLIENT_DISCONNECTED,
} TCP_Client_Status;

typedef struct TCP_Client_Connection TCP_Client_Connection;

const uint8_t *_Nonnull tcp_con_public_key(const TCP_Client_Connection *_Nonnull con);
IP_Port tcp_con_ip_port(const TCP_Client_Connection *_Nonnull con);
TCP_Client_Status tcp_con_status(const TCP_Client_Connection *_Nonnull con);

void *_Nullable tcp_con_custom_object(const TCP_Client_Connection *_Nonnull con);
uint32_t tcp_con_custom_uint(const TCP_Client_Connection *_Nonnull con);
void tcp_con_set_custom_object(TCP_Client_Connection *_Nonnull con, void *_Nonnull object);
void tcp_con_set_custom_uint(TCP_Client_Connection *_Nonnull con, uint32_t value);

/** Create new TCP connection to ip_port/public_key */
TCP_Client_Connection *_Nullable new_tcp_connection(
    const Logger *_Nonnull logger, const Memory *_Nonnull mem, const Mono_Time *_Nonnull mono_time, const Random *_Nonnull rng, const Network *_Nonnull ns,
    const IP_Port *_Nonnull ip_port, const uint8_t *_Nonnull public_key, const uint8_t *_Nonnull self_public_key, const uint8_t *_Nonnull self_secret_key,
    const TCP_Proxy_Info *_Nullable proxy_info, Net_Profile *_Nullable net_profile);
/** Run the TCP connection */
void do_tcp_connection(const Logger *_Nonnull logger, const Mono_Time *_Nonnull mono_time,
                       TCP_Client_Connection *_Nonnull tcp_connection, void *_Nullable userdata);
/** Kill the TCP connection */
void kill_tcp_connection(TCP_Client_Connection *_Nullable tcp_connection);
typedef int tcp_onion_response_cb(void *_Nonnull object, const uint8_t *_Nonnull data, uint16_t length, void *_Nullable userdata);

/**
 * @retval 1 on success.
 * @retval 0 if could not send packet.
 * @retval -1 on failure (connection must be killed).
 */
int send_onion_request(const Logger *_Nonnull logger, TCP_Client_Connection *_Nonnull con, const uint8_t *_Nonnull data, uint16_t length);
void onion_response_handler(TCP_Client_Connection *_Nonnull con, tcp_onion_response_cb *_Nonnull onion_callback, void *_Nonnull object);

int send_forward_request_tcp(const Logger *_Nonnull logger, TCP_Client_Connection *_Nonnull con, const IP_Port *_Nonnull dest, const uint8_t *_Nonnull data, uint16_t length);
void forwarding_handler(TCP_Client_Connection *_Nonnull con, forwarded_response_cb *_Nonnull forwarded_response_callback, void *_Nonnull object);

typedef int tcp_routing_response_cb(void *_Nonnull object, uint8_t connection_id, const uint8_t *_Nonnull public_key);
typedef int tcp_routing_status_cb(void *_Nonnull object, uint32_t number, uint8_t connection_id, uint8_t status);

/**
 * @retval 1 on success.
 * @retval 0 if could not send packet.
 * @retval -1 on failure (connection must be killed).
 */
int send_routing_request(const Logger *_Nonnull logger, TCP_Client_Connection *_Nonnull con, const uint8_t *_Nonnull public_key);
void routing_response_handler(TCP_Client_Connection *_Nonnull con, tcp_routing_response_cb *_Nonnull response_callback, void *_Nonnull object);
void routing_status_handler(TCP_Client_Connection *_Nonnull con, tcp_routing_status_cb *_Nonnull status_callback, void *_Nonnull object);

/**
 * @retval 1 on success.
 * @retval 0 if could not send packet.
 * @retval -1 on failure (connection must be killed).
 */
int send_disconnect_request(const Logger *_Nonnull logger, TCP_Client_Connection *_Nonnull con, uint8_t con_id);

/** @brief Set the number that will be used as an argument in the callbacks related to con_id.
 *
 * When not set by this function, the number is -1.
 *
 * return 0 on success.
 * return -1 on failure.
 */
int set_tcp_connection_number(TCP_Client_Connection *_Nonnull con, uint8_t con_id, uint32_t number);

typedef int tcp_routing_data_cb(void *_Nonnull object, uint32_t number, uint8_t connection_id, const uint8_t *_Nonnull data,
                                uint16_t length, void *_Nullable userdata);

/**
 * @retval 1 on success.
 * @retval 0 if could not send packet.
 * @retval -1 on failure.
 */
int send_data(const Logger *_Nonnull logger, TCP_Client_Connection *_Nonnull con, uint8_t con_id, const uint8_t *_Nonnull data, uint16_t length);
void routing_data_handler(TCP_Client_Connection *_Nonnull con, tcp_routing_data_cb *_Nonnull data_callback, void *_Nonnull object);

typedef int tcp_oob_data_cb(void *_Nonnull object, const uint8_t *_Nonnull public_key, const uint8_t *_Nonnull data, uint16_t length,
                            void *_Nullable userdata);

/**
 * @retval 1 on success.
 * @retval 0 if could not send packet.
 * @retval -1 on failure.
 */
int send_oob_packet(const Logger *_Nonnull logger, TCP_Client_Connection *_Nonnull con, const uint8_t *_Nonnull public_key, const uint8_t *_Nonnull data, uint16_t length);
void oob_data_handler(TCP_Client_Connection *_Nonnull con, tcp_oob_data_cb *_Nonnull oob_data_callback, void *_Nonnull object);

#ifdef __cplusplus
} /* extern "C" */
#endif

#endif /* C_TOXCORE_TOXCORE_TCP_CLIENT_H */
