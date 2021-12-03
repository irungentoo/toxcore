/* SPDX-License-Identifier: GPL-3.0-or-later
 * Copyright © 2016-2018 The TokTok team.
 * Copyright © 2014 Tox project.
 */

/*
 * Connection to friends.
 */
#ifndef C_TOXCORE_TOXCORE_FRIEND_CONNECTION_H
#define C_TOXCORE_TOXCORE_FRIEND_CONNECTION_H

#include "DHT.h"
#include "LAN_discovery.h"
#include "net_crypto.h"
#include "onion_client.h"

#define MAX_FRIEND_CONNECTION_CALLBACKS 2
#define MESSENGER_CALLBACK_INDEX 0
#define GROUPCHAT_CALLBACK_INDEX 1

#define PACKET_ID_ALIVE 16
#define PACKET_ID_SHARE_RELAYS 17
#define PACKET_ID_FRIEND_REQUESTS 18

/* Interval between the sending of ping packets. */
#define FRIEND_PING_INTERVAL 8

/* If no packets are received from friend in this time interval, kill the connection. */
#define FRIEND_CONNECTION_TIMEOUT (FRIEND_PING_INTERVAL * 4)

/* Time before friend is removed from the DHT after last hearing about him. */
#define FRIEND_DHT_TIMEOUT BAD_NODE_TIMEOUT

#define FRIEND_MAX_STORED_TCP_RELAYS (MAX_FRIEND_TCP_CONNECTIONS * 4)

/* Max number of tcp relays sent to friends */
#define MAX_SHARED_RELAYS RECOMMENDED_FRIEND_TCP_CONNECTIONS

/* Interval between the sending of tcp relay information */
#define SHARE_RELAYS_INTERVAL (5 * 60)


typedef enum Friendconn_Status {
    FRIENDCONN_STATUS_NONE,
    FRIENDCONN_STATUS_CONNECTING,
    FRIENDCONN_STATUS_CONNECTED,
} Friendconn_Status;

typedef struct Friend_Connections Friend_Connections;

Net_Crypto *friendconn_net_crypto(const Friend_Connections *fr_c);

/* return friendcon_id corresponding to the real public key on success.
 * return -1 on failure.
 */
int getfriend_conn_id_pk(Friend_Connections *fr_c, const uint8_t *real_pk);

/* Increases lock_count for the connection with friendcon_id by 1.
 *
 * return 0 on success.
 * return -1 on failure.
 */
int friend_connection_lock(Friend_Connections *fr_c, int friendcon_id);

/* return FRIENDCONN_STATUS_CONNECTED if the friend is connected.
 * return FRIENDCONN_STATUS_CONNECTING if the friend isn't connected.
 * return FRIENDCONN_STATUS_NONE on failure.
 */
unsigned int friend_con_connected(Friend_Connections *fr_c, int friendcon_id);

/* Copy public keys associated to friendcon_id.
 *
 * return 0 on success.
 * return -1 on failure.
 */
int get_friendcon_public_keys(uint8_t *real_pk, uint8_t *dht_temp_pk, Friend_Connections *fr_c, int friendcon_id);

/* Set temp dht key for connection.
 */
void set_dht_temp_pk(Friend_Connections *fr_c, int friendcon_id, const uint8_t *dht_temp_pk, void *userdata);

/* Add a TCP relay associated to the friend.
 *
 * return -1 on failure.
 * return 0 on success.
 */
int friend_add_tcp_relay(Friend_Connections *fr_c, int friendcon_id, IP_Port ip_port, const uint8_t *public_key);

typedef int global_status_cb(void *object, int id, uint8_t status, void *userdata);

typedef int fc_status_cb(void *object, int id, uint8_t status, void *userdata);
typedef int fc_data_cb(void *object, int id, const uint8_t *data, uint16_t length, void *userdata);
typedef int fc_lossy_data_cb(void *object, int id, const uint8_t *data, uint16_t length, void *userdata);

/* Set global status callback for friend connections. */
void set_global_status_callback(Friend_Connections *fr_c, global_status_cb *global_status_callback, void *object);

/* Set the callbacks for the friend connection.
 * index is the index (0 to (MAX_FRIEND_CONNECTION_CALLBACKS - 1)) we want the callback to set in the array.
 *
 * return 0 on success.
 * return -1 on failure
 */
int friend_connection_callbacks(Friend_Connections *fr_c, int friendcon_id, unsigned int index,
                                fc_status_cb *status_callback,
                                fc_data_cb *data_callback,
                                fc_lossy_data_cb *lossy_data_callback,
                                void *object, int number);

/* return the crypt_connection_id for the connection.
 *
 * return crypt_connection_id on success.
 * return -1 on failure.
 */
int friend_connection_crypt_connection_id(Friend_Connections *fr_c, int friendcon_id);

/* Create a new friend connection.
 * If one to that real public key already exists, increase lock count and return it.
 *
 * return -1 on failure.
 * return connection id on success.
 */
int new_friend_connection(Friend_Connections *fr_c, const uint8_t *real_public_key);

/* Kill a friend connection.
 *
 * return -1 on failure.
 * return 0 on success.
 */
int kill_friend_connection(Friend_Connections *fr_c, int friendcon_id);

/* Send a Friend request packet.
 *
 *  return -1 if failure.
 *  return  0 if it sent the friend request directly to the friend.
 *  return the number of peers it was routed through if it did not send it directly.
 */
int send_friend_request_packet(Friend_Connections *fr_c, int friendcon_id, uint32_t nospam_num, const uint8_t *data,
                               uint16_t length);

typedef int fr_request_cb(void *object, const uint8_t *source_pubkey, const uint8_t *data, uint16_t len,
                          void *userdata);

/* Set friend request callback.
 *
 * This function will be called every time a friend request is received.
 */
void set_friend_request_callback(Friend_Connections *fr_c, fr_request_cb *fr_request_callback, void *object);

/* Create new friend_connections instance. */
Friend_Connections *new_friend_connections(const Logger *logger, const Mono_Time *mono_time, Onion_Client *onion_c,
        bool local_discovery_enabled);

/* main friend_connections loop. */
void do_friend_connections(Friend_Connections *fr_c, void *userdata);

/* Free everything related with friend_connections. */
void kill_friend_connections(Friend_Connections *fr_c);

#endif
