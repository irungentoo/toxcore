/* tox_connection.h
 *
 * Connection to tox instances.
 *
 *  Copyright (C) 2014 Tox project All Rights Reserved.
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


#ifndef TOX_CONNECTION_H
#define TOX_CONNECTION_H

#include "net_crypto.h"
#include "DHT.h"
#include "LAN_discovery.h"
#include "onion_client.h"


#define MAX_TOX_CONNECTION_CALLBACKS 2
#define MESSENGER_CALLBACK_INDEX 0
#define GROUPCHAT_CALLBACK_INDEX 1

#define PACKET_ID_ALIVE 16
#define PACKET_ID_SHARE_RELAYS 17
#define PACKET_ID_FRIEND_REQUESTS 18

/* Interval between the sending of ping packets. */
#define TOXCONN_PING_INTERVAL 8

/* If no packets are received from peer in this time interval, kill the connection. */
#define TOXCONN_TIMEOUT (TOXCONN_PING_INTERVAL * 4)

/* Time before peer is removed from the DHT after last time we've heard about them. */
#define FRIEND_DHT_TIMEOUT BAD_NODE_TIMEOUT

#define TOXCONN_MAX_STORED_TCP_RELAYS (MAX_TCP_CONNECTIONS * 4)

/* Max number of tcp relays sent to peers */
#define MAX_SHARED_RELAYS (RECOMMENDED_TCP_CONNECTIONS_FRIENDS)

/* Interval between the sending of tcp relay information */
#define SHARE_RELAYS_INTERVAL (5 * 60)


enum {
    TOXCONN_STATUS_NONE,
    TOXCONN_STATUS_CONNECTING,
    TOXCONN_STATUS_CONNECTED
};

typedef struct {
    uint8_t status;

    uint8_t real_public_key[crypto_box_PUBLICKEYBYTES];
    uint8_t dht_temp_pk[crypto_box_PUBLICKEYBYTES];
    uint16_t dht_lock;
    IP_Port dht_ip_port;
    uint64_t dht_pk_lastrecv, dht_ip_port_lastrecv;

    int onion_friendnum;
    int crypt_connection_id;

    uint64_t ping_lastrecv, ping_lastsent;
    uint64_t share_relays_lastsent;

    struct {
        int (*status_callback)(void *object, int id, uint8_t status);
        void *status_callback_object;
        int status_callback_id;

        int (*data_callback)(void *object, int id, uint8_t *data, uint16_t length);
        void *data_callback_object;
        int data_callback_id;

        int (*lossy_data_callback)(void *object, int id, const uint8_t *data, uint16_t length);
        void *lossy_data_callback_object;
        int lossy_data_callback_id;
    } callbacks[MAX_TOX_CONNECTION_CALLBACKS];

    uint16_t lock_count;

    Node_format tcp_relays[TOXCONN_MAX_STORED_TCP_RELAYS];
    uint16_t tcp_relay_counter;

    _Bool hosting_tcp_relay;
} Tox_Conn;


typedef struct {
    Net_Crypto *net_crypto;
    DHT *dht;
    Onion_Client *onion_c;

    Tox_Conn *conns;
    uint32_t num_cons;

    int (*toxconn_request_callback)(void *object, const uint8_t *source_pubkey, const uint8_t *data, uint16_t len);
    void *toxconn_request_object;

    uint64_t last_LANdiscovery;
} Tox_Connections;

/* return toxconn_id corresponding to the real public key on success.
 * return -1 on failure.
 */
int gettox_conn_id_pk(Tox_Connections *tox_conns, const uint8_t *real_pk);

/* Increases lock_count for the connection with toxconn_id by 1.
 *
 * return 0 on success.
 * return -1 on failure.
 */
int tox_connection_lock(Tox_Connections *tox_conns, int toxconn_id);

/* return TOXCONN_STATUS_CONNECTED if the peer is connected.
 * return TOXCONN_STATUS_CONNECTING if the peer isn't connected.
 * return TOXCONN_STATUS_NONE on failure.
 */
unsigned int tox_conn_is_connected(Tox_Connections *tox_conns, int toxconn_id);

/* Copy public keys associated to toxconn_id.
 *
 * return 0 on success.
 * return -1 on failure.
 */
int tox_conn_get_public_keys(uint8_t *real_pk, uint8_t *dht_temp_pk, Tox_Connections *tox_conns, int toxconn_id);

/* Set temp dht key for connection.
 */
void set_dht_temp_pk(Tox_Connections *tox_conns, int toxconn_id, const uint8_t *dht_temp_pk);

/* Add a TCP relay associated to the connection.
 *
 * return -1 on failure.
 * return 0 on success.
 */
int toxconn_add_tcp_relay(Tox_Connections *tox_conns, int toxconn_id, IP_Port ip_port, const uint8_t *public_key);

/* Set the callbacks for the tox connection.
 * index is the index (0 to (MAX_TOX_CONNECTION_CALLBACKS - 1)) we want the callback to set in the array.
 *
 * return 0 on success.
 * return -1 on failure
 */
int tox_conn_set_callbacks(Tox_Connections *tox_conns, int toxconn_id, unsigned int index,
                                int (*status_callback)(void *object, int id, uint8_t status),
                                int (*data_callback)(void *object, int id, uint8_t *data, uint16_t length),
                                int (*lossy_data_callback)(void *object, int id, const uint8_t *data, uint16_t length),
                                void *object, int number);

/* return the crypt_connection_id for the connection.
 *
 * return crypt_connection_id on success.
 * return -1 on failure.
 */
int tox_conn_crypt_connection_id(Tox_Connections *tox_conns, int toxconn_id);

/* Create a new tox connection.
 * If one to that real public key already exists, increase lock count and return it.
 *
 * return -1 on failure.
 * return connection id on success.
 */
int new_tox_conn(Tox_Connections *tox_conns, const uint8_t *real_public_key);

/* Kill a tox connection.
 *
 * return -1 on failure.
 * return 0 on success.
 */
int kill_tox_conn(Tox_Connections *tox_conns, int toxconn_id);

/* Send a connection request packet.
 *
 *  return -1 if failure.
 *  return  0 if it sent the connection request was received directly.
 *  return the number of peers it was routed through if it did not send it directly.
 */
int send_tox_conn_request_pkt(Tox_Connections *tox_conns, int toxconn_id, uint32_t nospam_num, const uint8_t *data,
                               uint16_t length);

/* Set connection request callback.
 *
 * This function will be called every time a connection request is received.
 */
void set_tox_conn_request_callback(Tox_Connections *tox_conns,
                                   int (*toxconn_request_callback)(void *, const uint8_t *,const uint8_t *, uint16_t),
                                   void *object);

/* Create new tox_connections instance. */
Tox_Connections *new_tox_conns(Onion_Client *onion_c);

/* main tox_connections loop. */
void do_tox_connections(Tox_Connections *tox_conns);

/* Free everything related with given tox_connections. */
void kill_tox_conns(Tox_Connections *tox_conns);

#endif
