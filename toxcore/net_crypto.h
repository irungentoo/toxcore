/* net_crypto.h
 *
 * Functions for the core network crypto.
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

#ifndef NET_CRYPTO_H
#define NET_CRYPTO_H

#include "Lossless_UDP.h"
#include "DHT.h"

#define CRYPTO_HANDSHAKE_TIMEOUT (CONNECTION_TIMEOUT * 2)

#define CRYPTO_CONN_NO_CONNECTION 0
#define CRYPTO_CONN_HANDSHAKE_SENT 1
#define CRYPTO_CONN_NOT_CONFIRMED 2
#define CRYPTO_CONN_ESTABLISHED 3
#define CRYPTO_CONN_TIMED_OUT 4

typedef struct {
    uint8_t public_key[crypto_box_PUBLICKEYBYTES]; /* The real public key of the peer. */
    uint8_t recv_nonce[crypto_box_NONCEBYTES]; /* Nonce of received packets. */
    uint8_t sent_nonce[crypto_box_NONCEBYTES]; /* Nonce of sent packets. */
    uint8_t sessionpublic_key[crypto_box_PUBLICKEYBYTES]; /* Our public key for this session. */
    uint8_t sessionsecret_key[crypto_box_SECRETKEYBYTES]; /* Our private key for this session. */
    uint8_t peersessionpublic_key[crypto_box_PUBLICKEYBYTES]; /* The public key of the peer. */
    uint8_t shared_key[crypto_box_BEFORENMBYTES]; /* The precomputed shared key from encrypt_precompute. */
    uint8_t status; /* 0 if no connection, 1 we have sent a handshake, 2 if connection is not confirmed yet
                     * (we have received a handshake but no empty data packet), 3 if the connection is established.
                     * 4 if the connection is timed out.
                     */
    uint16_t number; /* Lossless_UDP connection number corresponding to this connection. */
    uint64_t timeout;

} Crypto_Connection;


typedef struct {
    Lossless_UDP *lossless_udp;
    DHT *dht;

    Crypto_Connection *crypto_connections;

    uint32_t crypto_connections_length; /* Length of connections array. */

    /* Our public and secret keys. */
    uint8_t self_public_key[crypto_box_PUBLICKEYBYTES];
    uint8_t self_secret_key[crypto_box_SECRETKEYBYTES];

    /* The secret key used for cookies */
    uint8_t secret_symmetric_key[crypto_box_KEYBYTES];
} Net_Crypto;

#include "DHT.h"

/*  return 0 if there is no received data in the buffer.
 *  return -1  if the packet was discarded.
 *  return length of received data if successful.
 */
int read_cryptpacket(Net_Crypto *c, int crypt_connection_id, uint8_t *data);

/* returns the number of packet slots left in the sendbuffer.
 * return 0 if failure.
 */
uint32_t crypto_num_free_sendqueue_slots(Net_Crypto *c, int crypt_connection_id);

/*  return 0 if data could not be put in packet queue.
 *  return 1 if data was put into the queue.
 */
int write_cryptpacket(Net_Crypto *c, int crypt_connection_id, uint8_t *data, uint32_t length);

/* Start a secure connection with other peer who has public_key and ip_port.
 *
 *  return -1 if failure.
 *  return crypt_connection_id of the initialized connection if everything went well.
 */
int crypto_connect(Net_Crypto *c, uint8_t *public_key, IP_Port ip_port);

/* Kill a crypto connection.
 *
 *  return 0 if killed successfully.
 *  return 1 if there was a problem.
 */
int crypto_kill(Net_Crypto *c, int crypt_connection_id);

/* Handle an incoming connection.
 *
 *  return -1 if no crypto inbound connection.
 *  return incoming connection id (Lossless_UDP one) if there is an incoming crypto connection.
 *
 *  Put the public key of the peer in public_key, the secret_nonce from the handshake into secret_nonce
 *  and the session public key for the connection in session_key.
 *  to accept it see: accept_crypto_inbound(...).
 *  to refuse it just call kill_connection(...) on the connection id.
 */
int crypto_inbound(Net_Crypto *c, uint8_t *public_key, uint8_t *secret_nonce, uint8_t *session_key);

/* Accept an incoming connection using the parameters provided by crypto_inbound.
 *
 *  return -1 if not successful.
 *  return crypt_connection_id if successful.
 */
int accept_crypto_inbound(Net_Crypto *c, int connection_id, uint8_t *public_key, uint8_t *secret_nonce,
                          uint8_t *session_key);

/*  return 0 if no connection.
 *  return 1 we have sent a handshake
 *  return 2 if connexion is not confirmed yet (we have received a handshake but no empty data packet).
 *  return 3 if the connection is established.
 *  return 4 if the connection is timed out and waiting to be killed.
 */
int is_cryptoconnected(Net_Crypto *c, int crypt_connection_id);


/* Generate our public and private keys.
 *  Only call this function the first time the program starts.
 */
void new_keys(Net_Crypto *c);

/* Save the public and private keys to the keys array.
 *  Length must be crypto_box_PUBLICKEYBYTES + crypto_box_SECRETKEYBYTES.
 */
void save_keys(Net_Crypto *c, uint8_t *keys);

/* Load the public and private keys from the keys array.
 *  Length must be crypto_box_PUBLICKEYBYTES + crypto_box_SECRETKEYBYTES.
 */
void load_keys(Net_Crypto *c, uint8_t *keys);

/* Create new instance of Net_Crypto.
 *  Sets all the global connection variables to their default values.
 */
Net_Crypto *new_net_crypto(DHT *dht);

/* Main loop. */
void do_net_crypto(Net_Crypto *c);

void kill_net_crypto(Net_Crypto *c);



#endif
