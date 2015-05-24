/* friend_connection.h
 *
 * Connection to friends.
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


#ifndef FRIEND_CONNECTION_H
#define FRIEND_CONNECTION_H

#include "net_crypto.h"
#include "DHT.h"
#include "LAN_discovery.h"
#include "onion_client.h"


#define MAX_FRIEND_CONNECTION_CALLBACKS 2
#define MESSENGER_CALLBACK_INDEX 0
#define GROUPCHAT_CALLBACK_INDEX 1

#define PACKET_ID_ALIVE 16
#define PACKET_ID_SHARE_RELAYS 17
#define PACKET_ID_FRIEND_REQUESTS 18

/* Interval between the sending of ping packets. */
#define FRIEND_PING_INTERVAL 7

/* If no packets are received from friend in this time interval, kill the connection. */
#define FRIEND_CONNECTION_TIMEOUT (FRIEND_PING_INTERVAL * 3)

/* Time before friend is removed from the DHT after last hearing about him. */
#define FRIEND_DHT_TIMEOUT BAD_NODE_TIMEOUT

#define FRIEND_MAX_STORED_TCP_RELAYS (MAX_FRIEND_TCP_CONNECTIONS * 4)

/* Max number of tcp relays sent to friends */
#define MAX_SHARED_RELAYS (RECOMMENDED_FRIEND_TCP_CONNECTIONS)

/* Interval between the sending of tcp relay information */
#define SHARE_RELAYS_INTERVAL (5 * 60)


enum {
    FRIENDCONN_STATUS_NONE,
    FRIENDCONN_STATUS_CONNECTING,
    FRIENDCONN_STATUS_CONNECTED
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
    } callbacks[MAX_FRIEND_CONNECTION_CALLBACKS];

    uint16_t lock_count;

    Node_format tcp_relays[FRIEND_MAX_STORED_TCP_RELAYS];
    uint16_t tcp_relay_counter;

    _Bool hosting_tcp_relay;
} Friend_Conn;


typedef struct {
    Net_Crypto *net_crypto;
    DHT *dht;
    Onion_Client *onion_c;

    Friend_Conn *conns;
    uint32_t num_cons;

    int (*fr_request_callback)(void *object, const uint8_t *source_pubkey, const uint8_t *data, uint16_t len);
    void *fr_request_object;

    uint64_t last_LANdiscovery;
} Friend_Connections;

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
void set_dht_temp_pk(Friend_Connections *fr_c, int friendcon_id, const uint8_t *dht_temp_pk);

/* Add a TCP relay associated to the friend.
 *
 * return -1 on failure.
 * return 0 on success.
 */
int friend_add_tcp_relay(Friend_Connections *fr_c, int friendcon_id, IP_Port ip_port, const uint8_t *public_key);

/* Set the callbacks for the friend connection.
 * index is the index (0 to (MAX_FRIEND_CONNECTION_CALLBACKS - 1)) we want the callback to set in the array.
 *
 * return 0 on success.
 * return -1 on failure
 */
int friend_connection_callbacks(Friend_Connections *fr_c, int friendcon_id, unsigned int index,
                                int (*status_callback)(void *object, int id, uint8_t status), int (*data_callback)(void *object, int id, uint8_t *data,
                                        uint16_t length), int (*lossy_data_callback)(void *object, int id, const uint8_t *data, uint16_t length), void *object,
                                int number);

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

/* Set friend request callback.
 *
 * This function will be called every time a friend request is received.
 */
void set_friend_request_callback(Friend_Connections *fr_c, int (*fr_request_callback)(void *, const uint8_t *,
                                 const uint8_t *, uint16_t), void *object);

/* Create new friend_connections instance. */
Friend_Connections *new_friend_connections(Onion_Client *onion_c);

/* main friend_connections loop. */
void do_friend_connections(Friend_Connections *fr_c);

/* Free everything related with friend_connections. */
void kill_friend_connections(Friend_Connections *fr_c);

#endif
