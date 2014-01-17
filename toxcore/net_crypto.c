/* net_crypto.c
 *
 * Functions for the core network crypto.
 * See also: http://wiki.tox.im/index.php/DHT
 *
 * NOTE: This code has to be perfect. We don't mess around with encryption.
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

#include "net_crypto.h"
#include "util.h"
static uint8_t crypt_connection_id_not_valid(Net_Crypto *c, int crypt_connection_id)
{
    return (uint32_t)crypt_connection_id >= c->crypto_connections_length;
}

/* Use this instead of memcmp; not vulnerable to timing attacks. */
uint8_t crypto_iszero(uint8_t *mem, uint32_t length)
{
    uint8_t check = 0;
    uint32_t i;

    for (i = 0; i < length; ++i) {
        check |= mem[i];
    }

    return check; // We return zero if mem is made out of zeroes.
}

/* Precomputes the shared key from their public_key and our secret_key.
 * This way we can avoid an expensive elliptic curve scalar multiply for each
 * encrypt/decrypt operation.
 * enc_key has to be crypto_box_BEFORENMBYTES bytes long.
 */
void encrypt_precompute(uint8_t *public_key, uint8_t *secret_key, uint8_t *enc_key)
{
    crypto_box_beforenm(enc_key, public_key, secret_key);
}

/* Fast encrypt. Depends on enc_key from encrypt_precompute. */
int encrypt_data_fast(uint8_t *enc_key, uint8_t *nonce,
                      uint8_t *plain, uint32_t length, uint8_t *encrypted)
{
    if (length + crypto_box_MACBYTES > MAX_DATA_SIZE || length == 0)
        return -1;

    uint8_t temp_plain[MAX_DATA_SIZE + crypto_box_ZEROBYTES] = {0};
    uint8_t temp_encrypted[MAX_DATA_SIZE + crypto_box_BOXZEROBYTES];

    memcpy(temp_plain + crypto_box_ZEROBYTES, plain, length); // Pad the message with 32 0 bytes.

    crypto_box_afternm(temp_encrypted, temp_plain, length + crypto_box_ZEROBYTES, nonce, enc_key);

    if (crypto_iszero(temp_encrypted, crypto_box_BOXZEROBYTES) != 0)
        return -1;

    /* Unpad the encrypted message. */
    memcpy(encrypted, temp_encrypted + crypto_box_BOXZEROBYTES, length + crypto_box_MACBYTES);
    return length + crypto_box_MACBYTES;
}

/* Fast decrypt. Depends on enc_ley from encrypt_precompute. */
int decrypt_data_fast(uint8_t *enc_key, uint8_t *nonce,
                      uint8_t *encrypted, uint32_t length, uint8_t *plain)
{
    if (length > MAX_DATA_SIZE || length <= crypto_box_BOXZEROBYTES)
        return -1;

    uint8_t temp_plain[MAX_DATA_SIZE + crypto_box_ZEROBYTES];
    uint8_t temp_encrypted[MAX_DATA_SIZE + crypto_box_BOXZEROBYTES] = {0};

    memcpy(temp_encrypted + crypto_box_BOXZEROBYTES, encrypted, length); // Pad the message with 16 0 bytes.

    if (crypto_box_open_afternm(temp_plain, temp_encrypted, length + crypto_box_BOXZEROBYTES,
                                nonce, enc_key) == -1)
        return -1;

    /* If decryption is successful the first crypto_box_ZEROBYTES of the message will be zero.
     * Apparently memcmp should not be used so we do this instead:
     */
    if (crypto_iszero(temp_plain, crypto_box_ZEROBYTES) != 0)
        return -1;

    /* Unpad the plain message. */
    memcpy(plain, temp_plain + crypto_box_ZEROBYTES, length - crypto_box_MACBYTES);
    return length - crypto_box_MACBYTES;
}

int encrypt_data(uint8_t *public_key, uint8_t *secret_key, uint8_t *nonce,
                 uint8_t *plain, uint32_t length, uint8_t *encrypted)
{
    uint8_t k[crypto_box_BEFORENMBYTES];
    encrypt_precompute(public_key, secret_key, k);
    return encrypt_data_fast(k, nonce, plain, length, encrypted);
}

int decrypt_data(uint8_t *public_key, uint8_t *secret_key, uint8_t *nonce,
                 uint8_t *encrypted, uint32_t length, uint8_t *plain)
{
    uint8_t k[crypto_box_BEFORENMBYTES];
    encrypt_precompute(public_key, secret_key, k);
    return decrypt_data_fast(k, nonce, encrypted, length, plain);
}

int encrypt_data_symmetric(uint8_t *secret_key, uint8_t *nonce, uint8_t *plain, uint32_t length, uint8_t *encrypted)
{
    if (length == 0)
        return -1;

    uint8_t temp_plain[length + crypto_secretbox_ZEROBYTES];
    uint8_t temp_encrypted[length + crypto_secretbox_MACBYTES + crypto_secretbox_BOXZEROBYTES];

    memset(temp_plain, 0, crypto_secretbox_ZEROBYTES);
    memcpy(temp_plain + crypto_secretbox_ZEROBYTES, plain, length); // Pad the message with 32 0 bytes.

    crypto_secretbox(temp_encrypted, temp_plain, length + crypto_secretbox_ZEROBYTES, nonce, secret_key);
    /* Unpad the encrypted message. */
    memcpy(encrypted, temp_encrypted + crypto_secretbox_BOXZEROBYTES, length + crypto_secretbox_MACBYTES);
    return length + crypto_secretbox_MACBYTES;
}

int decrypt_data_symmetric(uint8_t *secret_key, uint8_t *nonce, uint8_t *encrypted, uint32_t length, uint8_t *plain)
{
    if (length <= crypto_secretbox_BOXZEROBYTES)
        return -1;

    uint8_t temp_plain[length + crypto_secretbox_ZEROBYTES];
    uint8_t temp_encrypted[length + crypto_secretbox_BOXZEROBYTES];

    memset(temp_plain, 0, crypto_secretbox_BOXZEROBYTES);
    memcpy(temp_encrypted + crypto_secretbox_BOXZEROBYTES, encrypted, length); // Pad the message with 16 0 bytes.

    if (crypto_secretbox_open(temp_plain, temp_encrypted, length + crypto_secretbox_BOXZEROBYTES, nonce, secret_key) == -1)
        return -1;

    memcpy(plain, temp_plain + crypto_secretbox_ZEROBYTES, length - crypto_secretbox_MACBYTES);
    return length - crypto_secretbox_MACBYTES;
}

/* Increment the given nonce by 1. */
static void increment_nonce(uint8_t *nonce)
{
    uint32_t i;

    for (i = 0; i < crypto_box_NONCEBYTES; ++i) {
        ++nonce[i];

        if (nonce[i] != 0)
            break;
    }
}

#if crypto_box_NONCEBYTES != crypto_secretbox_NONCEBYTES
/*if they no longer equal each other, this function must be split into two.*/
#error random_nonce(): crypto_box_NONCEBYTES must equal crypto_secretbox_NONCEBYTES.
#endif
/* Fill the given nonce with random bytes. */
void random_nonce(uint8_t *nonce)
{
    randombytes(nonce, crypto_box_NONCEBYTES);
}

/* Fill a key crypto_secretbox_KEYBYTES big with random bytes */
void new_symmetric_key(uint8_t *key)
{
    randombytes(key, crypto_secretbox_KEYBYTES);
}

static uint8_t base_nonce[crypto_box_NONCEBYTES];
static uint8_t nonce_set = 0;

#if crypto_box_NONCEBYTES != crypto_secretbox_NONCEBYTES
/*if they no longer equal each other, this function must be split into two.*/
#error new_nonce(): crypto_box_NONCEBYTES must equal crypto_secretbox_NONCEBYTES.
#endif
/* Gives a nonce guaranteed to be different from previous ones.*/
void new_nonce(uint8_t *nonce)
{
    if (nonce_set == 0) {
        random_nonce(base_nonce);
        nonce_set = 1;
    }

    increment_nonce(base_nonce);
    memcpy(nonce, base_nonce, crypto_box_NONCEBYTES);
}


/*  return 0 if there is no received data in the buffer.
 *  return -1  if the packet was discarded.
 *  return length of received data if successful.
 */
int read_cryptpacket(Net_Crypto *c, int crypt_connection_id, uint8_t *data)
{
    if (crypt_connection_id_not_valid(c, crypt_connection_id))
        return 0;

    if (c->crypto_connections[crypt_connection_id].status != CRYPTO_CONN_ESTABLISHED)
        return 0;

    uint8_t temp_data[MAX_DATA_SIZE];
    int length = read_packet(c->lossless_udp, c->crypto_connections[crypt_connection_id].number, temp_data);

    if (length == 0)
        return 0;

    if (temp_data[0] != 3)
        return -1;

    int len = decrypt_data_fast(c->crypto_connections[crypt_connection_id].shared_key,
                                c->crypto_connections[crypt_connection_id].recv_nonce,
                                temp_data + 1, length - 1, data);

    if (len != -1) {
        increment_nonce(c->crypto_connections[crypt_connection_id].recv_nonce);
        return len;
    }

    return -1;
}

/* returns the number of packet slots left in the sendbuffer.
 * return 0 if failure.
 */
uint32_t crypto_num_free_sendqueue_slots(Net_Crypto *c, int crypt_connection_id)
{
    if (crypt_connection_id_not_valid(c, crypt_connection_id))
        return 0;

    return num_free_sendqueue_slots(c->lossless_udp, c->crypto_connections[crypt_connection_id].number);
}

/*  return 0 if data could not be put in packet queue.
 *  return 1 if data was put into the queue.
 */
int write_cryptpacket(Net_Crypto *c, int crypt_connection_id, uint8_t *data, uint32_t length)
{
    if (crypt_connection_id_not_valid(c, crypt_connection_id))
        return 0;

    if (length - crypto_box_BOXZEROBYTES + crypto_box_ZEROBYTES > MAX_DATA_SIZE - 1)
        return 0;

    if (c->crypto_connections[crypt_connection_id].status != CRYPTO_CONN_ESTABLISHED)
        return 0;

    uint8_t temp_data[MAX_DATA_SIZE];
    int len = encrypt_data_fast(c->crypto_connections[crypt_connection_id].shared_key,
                                c->crypto_connections[crypt_connection_id].sent_nonce,
                                data, length, temp_data + 1);

    if (len == -1)
        return 0;

    temp_data[0] = 3;

    if (write_packet(c->lossless_udp, c->crypto_connections[crypt_connection_id].number, temp_data, len + 1) == 0)
        return 0;

    increment_nonce(c->crypto_connections[crypt_connection_id].sent_nonce);
    return 1;
}

/* Create a request to peer.
 * send_public_key and send_secret_key are the pub/secret keys of the sender.
 * recv_public_key is public key of reciever.
 * packet must be an array of MAX_DATA_SIZE big.
 * Data represents the data we send with the request with length being the length of the data.
 * request_id is the id of the request (32 = friend request, 254 = ping request).
 *
 *  return -1 on failure.
 *  return the length of the created packet on success.
 */
int create_request(uint8_t *send_public_key, uint8_t *send_secret_key, uint8_t *packet, uint8_t *recv_public_key,
                   uint8_t *data, uint32_t length, uint8_t request_id)
{
    if (MAX_DATA_SIZE < length + 1 + crypto_box_PUBLICKEYBYTES * 2 + crypto_box_NONCEBYTES + 1 + crypto_box_MACBYTES)
        return -1;

    uint8_t nonce[crypto_box_NONCEBYTES];
    uint8_t temp[MAX_DATA_SIZE];
    memcpy(temp + 1, data, length);
    temp[0] = request_id;
    new_nonce(nonce);
    int len = encrypt_data(recv_public_key, send_secret_key, nonce, temp, length + 1,
                           1 + crypto_box_PUBLICKEYBYTES * 2 + crypto_box_NONCEBYTES + packet);

    if (len == -1)
        return -1;

    packet[0] = NET_PACKET_CRYPTO;
    memcpy(packet + 1, recv_public_key, crypto_box_PUBLICKEYBYTES);
    memcpy(packet + 1 + crypto_box_PUBLICKEYBYTES, send_public_key, crypto_box_PUBLICKEYBYTES);
    memcpy(packet + 1 + crypto_box_PUBLICKEYBYTES * 2, nonce, crypto_box_NONCEBYTES);

    return len + 1 + crypto_box_PUBLICKEYBYTES * 2 + crypto_box_NONCEBYTES;
}

/* Puts the senders public key in the request in public_key, the data from the request
 * in data if a friend or ping request was sent to us and returns the length of the data.
 * packet is the request packet and length is its length.
 *
 *  return -1 if not valid request.
 */
int handle_request(uint8_t *self_public_key, uint8_t *self_secret_key, uint8_t *public_key, uint8_t *data,
                   uint8_t *request_id, uint8_t *packet, uint16_t length)
{
    if (length > crypto_box_PUBLICKEYBYTES * 2 + crypto_box_NONCEBYTES + 1 + crypto_box_MACBYTES &&
            length <= MAX_DATA_SIZE) {
        if (memcmp(packet + 1, self_public_key, crypto_box_PUBLICKEYBYTES) == 0) {
            memcpy(public_key, packet + 1 + crypto_box_PUBLICKEYBYTES, crypto_box_PUBLICKEYBYTES);
            uint8_t nonce[crypto_box_NONCEBYTES];
            uint8_t temp[MAX_DATA_SIZE];
            memcpy(nonce, packet + 1 + crypto_box_PUBLICKEYBYTES * 2, crypto_box_NONCEBYTES);
            int len1 = decrypt_data(public_key, self_secret_key, nonce,
                                    packet + 1 + crypto_box_PUBLICKEYBYTES * 2 + crypto_box_NONCEBYTES,
                                    length - (crypto_box_PUBLICKEYBYTES * 2 + crypto_box_NONCEBYTES + 1), temp);

            if (len1 == -1 || len1 == 0)
                return -1;

            request_id[0] = temp[0];
            --len1;
            memcpy(data, temp + 1, len1);
            return len1;
        }
    }

    return -1;
}

void cryptopacket_registerhandler(Net_Crypto *c, uint8_t byte, cryptopacket_handler_callback cb, void *object)
{
    c->cryptopackethandlers[byte].function = cb;
    c->cryptopackethandlers[byte].object = object;
}

static int cryptopacket_handle(void *object, IP_Port source, uint8_t *packet, uint32_t length)
{
    DHT *dht = object;

    if (packet[0] == NET_PACKET_CRYPTO) {
        if (length <= crypto_box_PUBLICKEYBYTES * 2 + crypto_box_NONCEBYTES + 1 + crypto_box_MACBYTES ||
                length > MAX_DATA_SIZE + crypto_box_MACBYTES)
            return 1;

        if (memcmp(packet + 1, dht->self_public_key, crypto_box_PUBLICKEYBYTES) == 0) { // Check if request is for us.
            uint8_t public_key[crypto_box_PUBLICKEYBYTES];
            uint8_t data[MAX_DATA_SIZE];
            uint8_t number;
            int len = handle_request(dht->self_public_key, dht->self_secret_key, public_key, data, &number, packet, length);

            if (len == -1 || len == 0)
                return 1;

            if (!dht->c->cryptopackethandlers[number].function) return 1;

            dht->c->cryptopackethandlers[number].function(dht->c->cryptopackethandlers[number].object, source, public_key, data,
                    len);

        } else { /* If request is not for us, try routing it. */
            int retval = route_packet(dht, packet + 1, packet, length);

            if ((unsigned int)retval == length)
                return 0;
        }
    }

    return 1;
}

/* Send a crypto handshake packet containing an encrypted secret nonce and session public key
 * to peer with connection_id and public_key.
 * The packet is encrypted with a random nonce which is sent in plain text with the packet.
 */
static int send_cryptohandshake(Net_Crypto *c, int connection_id, uint8_t *public_key, uint8_t *secret_nonce,
                                uint8_t *session_key)
{
    uint8_t temp_data[MAX_DATA_SIZE];
    uint8_t temp[crypto_box_NONCEBYTES + crypto_box_PUBLICKEYBYTES];
    uint8_t nonce[crypto_box_NONCEBYTES];

    new_nonce(nonce);
    memcpy(temp, secret_nonce, crypto_box_NONCEBYTES);
    memcpy(temp + crypto_box_NONCEBYTES, session_key, crypto_box_PUBLICKEYBYTES);

    int len = encrypt_data(public_key, c->self_secret_key, nonce, temp, crypto_box_NONCEBYTES + crypto_box_PUBLICKEYBYTES,
                           1 + crypto_box_PUBLICKEYBYTES + crypto_box_NONCEBYTES + temp_data);

    if (len == -1)
        return 0;

    temp_data[0] = 2;
    memcpy(temp_data + 1, c->self_public_key, crypto_box_PUBLICKEYBYTES);
    memcpy(temp_data + 1 + crypto_box_PUBLICKEYBYTES, nonce, crypto_box_NONCEBYTES);
    return write_packet(c->lossless_udp, connection_id, temp_data,
                        len + 1 + crypto_box_PUBLICKEYBYTES + crypto_box_NONCEBYTES);
}

/* Extract secret nonce, session public key and public_key from a packet(data) with length length.
 *
 *  return 1 if successful.
 *  return 0 if failure.
 */
static int handle_cryptohandshake(Net_Crypto *c, uint8_t *public_key, uint8_t *secret_nonce,
                                  uint8_t *session_key, uint8_t *data, uint16_t length)
{
    int pad = (- crypto_box_BOXZEROBYTES + crypto_box_ZEROBYTES);

    if (length != 1 + crypto_box_PUBLICKEYBYTES + crypto_box_NONCEBYTES
            + crypto_box_NONCEBYTES + crypto_box_PUBLICKEYBYTES + pad) {
        return 0;
    }

    if (data[0] != 2)
        return 0;

    uint8_t temp[crypto_box_NONCEBYTES + crypto_box_PUBLICKEYBYTES];

    memcpy(public_key, data + 1, crypto_box_PUBLICKEYBYTES);

    int len = decrypt_data(public_key, c->self_secret_key, data + 1 + crypto_box_PUBLICKEYBYTES,
                           data + 1 + crypto_box_PUBLICKEYBYTES + crypto_box_NONCEBYTES,
                           crypto_box_NONCEBYTES + crypto_box_PUBLICKEYBYTES + pad, temp);

    if (len != crypto_box_NONCEBYTES + crypto_box_PUBLICKEYBYTES)
        return 0;

    memcpy(secret_nonce, temp, crypto_box_NONCEBYTES);
    memcpy(session_key, temp + crypto_box_NONCEBYTES, crypto_box_PUBLICKEYBYTES);
    return 1;
}

/* Get crypto connection id from public key of peer.
 *
 *  return -1 if there are no connections like we are looking for.
 *  return id if it found it.
 */
static int getcryptconnection_id(Net_Crypto *c, uint8_t *public_key)
{
    uint32_t i;

    for (i = 0; i < c->crypto_connections_length; ++i) {
        if (c->crypto_connections[i].status != CRYPTO_CONN_NO_CONNECTION)
            if (memcmp(public_key, c->crypto_connections[i].public_key, crypto_box_PUBLICKEYBYTES) == 0)
                return i;
    }

    return -1;
}

/* Set the size of the friend list to numfriends.
 *
 *  return -1 if realloc fails.
 *  return 0 if it succeeds.
 */
static int realloc_cryptoconnection(Net_Crypto *c, uint32_t num)
{
    if (num == 0) {
        free(c->crypto_connections);
        c->crypto_connections = NULL;
        return 0;
    }

    Crypto_Connection *newcrypto_connections = realloc(c->crypto_connections, num * sizeof(Crypto_Connection));

    if (newcrypto_connections == NULL)
        return -1;

    c->crypto_connections = newcrypto_connections;
    return 0;
}

/* Start a secure connection with other peer who has public_key and ip_port.
 *
 *  return -1 if failure.
 *  return crypt_connection_id of the initialized connection if everything went well.
 */
int crypto_connect(Net_Crypto *c, uint8_t *public_key, IP_Port ip_port)
{
    uint32_t i;
    int id_existing = getcryptconnection_id(c, public_key);

    if (id_existing != -1) {
        IP_Port c_ip = connection_ip(c->lossless_udp, c->crypto_connections[id_existing].number);

        if (ipport_equal(&c_ip, &ip_port))
            return -1;
    }

    if (realloc_cryptoconnection(c, c->crypto_connections_length + 1) == -1
            || c->crypto_connections == NULL)
        return -1;

    memset(&(c->crypto_connections[c->crypto_connections_length]), 0, sizeof(Crypto_Connection));
    c->crypto_connections[c->crypto_connections_length].number = ~0;

    for (i = 0; i <= c->crypto_connections_length; ++i) {
        if (c->crypto_connections[i].status == CRYPTO_CONN_NO_CONNECTION) {
            int id_new = new_connection(c->lossless_udp, ip_port);

            if (id_new == -1)
                return -1;

            c->crypto_connections[i].number = id_new;
            c->crypto_connections[i].status = CRYPTO_CONN_HANDSHAKE_SENT;
            random_nonce(c->crypto_connections[i].recv_nonce);
            memcpy(c->crypto_connections[i].public_key, public_key, crypto_box_PUBLICKEYBYTES);
            crypto_box_keypair(c->crypto_connections[i].sessionpublic_key, c->crypto_connections[i].sessionsecret_key);
            c->crypto_connections[i].timeout = unix_time() + CRYPTO_HANDSHAKE_TIMEOUT;

            if (c->crypto_connections_length == i)
                ++c->crypto_connections_length;

            if (send_cryptohandshake(c, id_new, public_key,  c->crypto_connections[i].recv_nonce,
                                     c->crypto_connections[i].sessionpublic_key) == 1) {
                increment_nonce(c->crypto_connections[i].recv_nonce);
                return i;
            }

            return -1; /* This should never happen. */
        }
    }

    return -1;
}

/* Handle an incoming connection.
 *
 *  return -1 if no crypto inbound connection.
 *  return incoming connection id (Lossless_UDP one) if there is an incoming crypto connection.
 *
 * Put the public key of the peer in public_key, the secret_nonce from the handshake into secret_nonce
 * and the session public key for the connection in session_key.
 * to accept it see: accept_crypto_inbound(...).
 * to refuse it just call kill_connection(...) on the connection id.
 */
int crypto_inbound(Net_Crypto *c, uint8_t *public_key, uint8_t *secret_nonce, uint8_t *session_key)
{
    while (1) {
        int incoming_con = incoming_connection(c->lossless_udp, 1);

        if (incoming_con != -1) {
            if (is_connected(c->lossless_udp, incoming_con) == LUDP_TIMED_OUT) {
                kill_connection(c->lossless_udp, incoming_con);
                continue;
            }

            if (id_packet(c->lossless_udp, incoming_con) == 2) {
                uint8_t temp_data[MAX_DATA_SIZE];
                uint16_t len = read_packet_silent(c->lossless_udp, incoming_con, temp_data);

                if (handle_cryptohandshake(c, public_key, secret_nonce, session_key, temp_data, len)) {
                    return incoming_con;
                }
            }
        } else {
            break;
        }
    }

    return -1;
}

/* Kill a crypto connection.
 *
 *  return 0 if killed successfully.
 *  return 1 if there was a problem.
 */
int crypto_kill(Net_Crypto *c, int crypt_connection_id)
{
    if (crypt_connection_id_not_valid(c, crypt_connection_id))
        return 1;

    if (c->crypto_connections[crypt_connection_id].status != CRYPTO_CONN_NO_CONNECTION) {
        c->crypto_connections[crypt_connection_id].status = CRYPTO_CONN_NO_CONNECTION;
        kill_connection(c->lossless_udp, c->crypto_connections[crypt_connection_id].number);
        memset(&(c->crypto_connections[crypt_connection_id]), 0 , sizeof(Crypto_Connection));
        c->crypto_connections[crypt_connection_id].number = ~0;
        uint32_t i;

        for (i = c->crypto_connections_length; i != 0; --i) {
            if (c->crypto_connections[i - 1].status != CRYPTO_CONN_NO_CONNECTION)
                break;
        }

        if (c->crypto_connections_length != i) {
            c->crypto_connections_length = i;
            realloc_cryptoconnection(c, c->crypto_connections_length);
        }

        return 0;
    }

    return 1;
}

/* Accept an incoming connection using the parameters provided by crypto_inbound.
 *
 *  return -1 if not successful.
 *  return the crypt_connection_id if successful.
 */
int accept_crypto_inbound(Net_Crypto *c, int connection_id, uint8_t *public_key, uint8_t *secret_nonce,
                          uint8_t *session_key)
{
    uint32_t i;

    if (discard_packet(c->lossless_udp, connection_id) == -1)
        return -1;

    /*
     * if(getcryptconnection_id(public_key) != -1)
     * {
     *     return -1;
     * }
     */

    if (realloc_cryptoconnection(c, c->crypto_connections_length + 1) == -1
            || c->crypto_connections == NULL)
        return -1;

    memset(&(c->crypto_connections[c->crypto_connections_length]), 0, sizeof(Crypto_Connection));
    c->crypto_connections[c->crypto_connections_length].number = ~0;

    for (i = 0; i <= c->crypto_connections_length; ++i) {
        if (c->crypto_connections[i].status == CRYPTO_CONN_NO_CONNECTION) {
            c->crypto_connections[i].number = connection_id;
            c->crypto_connections[i].status = CRYPTO_CONN_NOT_CONFIRMED;
            c->crypto_connections[i].timeout = unix_time() + CRYPTO_HANDSHAKE_TIMEOUT;
            random_nonce(c->crypto_connections[i].recv_nonce);
            memcpy(c->crypto_connections[i].sent_nonce, secret_nonce, crypto_box_NONCEBYTES);
            memcpy(c->crypto_connections[i].peersessionpublic_key, session_key, crypto_box_PUBLICKEYBYTES);
            increment_nonce(c->crypto_connections[i].sent_nonce);
            memcpy(c->crypto_connections[i].public_key, public_key, crypto_box_PUBLICKEYBYTES);

            crypto_box_keypair(c->crypto_connections[i].sessionpublic_key, c->crypto_connections[i].sessionsecret_key);

            if (c->crypto_connections_length == i)
                ++c->crypto_connections_length;

            if (send_cryptohandshake(c, connection_id, public_key, c->crypto_connections[i].recv_nonce,
                                     c->crypto_connections[i].sessionpublic_key) == 1) {
                increment_nonce(c->crypto_connections[i].recv_nonce);
                uint32_t zero = 0;
                encrypt_precompute(c->crypto_connections[i].peersessionpublic_key,
                                   c->crypto_connections[i].sessionsecret_key,
                                   c->crypto_connections[i].shared_key);
                c->crypto_connections[i].status =
                    CRYPTO_CONN_ESTABLISHED; /* Connection status needs to be 3 for write_cryptpacket() to work. */
                write_cryptpacket(c, i, ((uint8_t *)&zero), sizeof(zero));
                c->crypto_connections[i].status = CRYPTO_CONN_NOT_CONFIRMED; /* Set it to its proper value right after. */
                return i;
            }

            return -1; /* This should never happen. */
        }
    }

    return -1;
}

/*  return 0 if no connection.
 *  return 1 we have sent a handshake.
 *  return 2 if connection is not confirmed yet (we have received a handshake but no empty data packet).
 *  return 3 if the connection is established.
 *  return 4 if the connection is timed out and waiting to be killed.
 */
int is_cryptoconnected(Net_Crypto *c, int crypt_connection_id)
{
    if ((unsigned int)crypt_connection_id < c->crypto_connections_length)
        return c->crypto_connections[crypt_connection_id].status;

    return CRYPTO_CONN_NO_CONNECTION;
}

void new_keys(Net_Crypto *c)
{
    crypto_box_keypair(c->self_public_key, c->self_secret_key);
}

/* Save the public and private keys to the keys array.
 * Length must be crypto_box_PUBLICKEYBYTES + crypto_box_SECRETKEYBYTES.
 */
void save_keys(Net_Crypto *c, uint8_t *keys)
{
    memcpy(keys, c->self_public_key, crypto_box_PUBLICKEYBYTES);
    memcpy(keys + crypto_box_PUBLICKEYBYTES, c->self_secret_key, crypto_box_SECRETKEYBYTES);
}

/* Load the public and private keys from the keys array.
 * Length must be crypto_box_PUBLICKEYBYTES + crypto_box_SECRETKEYBYTES.
 */
void load_keys(Net_Crypto *c, uint8_t *keys)
{
    memcpy(c->self_public_key, keys, crypto_box_PUBLICKEYBYTES);
    memcpy(c->self_secret_key, keys + crypto_box_PUBLICKEYBYTES, crypto_box_SECRETKEYBYTES);
}

/* Handle received packets for not yet established crypto connections. */
static void receive_crypto(Net_Crypto *c)
{
    uint32_t i;
    uint64_t temp_time = unix_time();

    for (i = 0; i < c->crypto_connections_length; ++i) {
        if (c->crypto_connections[i].status == CRYPTO_CONN_NO_CONNECTION)
            continue;

        if (c->crypto_connections[i].status == CRYPTO_CONN_HANDSHAKE_SENT) {
            uint8_t temp_data[MAX_DATA_SIZE];
            uint8_t secret_nonce[crypto_box_NONCEBYTES];
            uint8_t public_key[crypto_box_PUBLICKEYBYTES];
            uint8_t session_key[crypto_box_PUBLICKEYBYTES];
            uint16_t len;

            if (id_packet(c->lossless_udp, c->crypto_connections[i].number) == 2) { /* Handle handshake packet. */
                len = read_packet(c->lossless_udp, c->crypto_connections[i].number, temp_data);

                if (handle_cryptohandshake(c, public_key, secret_nonce, session_key, temp_data, len)) {
                    if (memcmp(public_key, c->crypto_connections[i].public_key, crypto_box_PUBLICKEYBYTES) == 0) {
                        memcpy(c->crypto_connections[i].sent_nonce, secret_nonce, crypto_box_NONCEBYTES);
                        memcpy(c->crypto_connections[i].peersessionpublic_key, session_key, crypto_box_PUBLICKEYBYTES);
                        increment_nonce(c->crypto_connections[i].sent_nonce);
                        uint32_t zero = 0;
                        encrypt_precompute(c->crypto_connections[i].peersessionpublic_key,
                                           c->crypto_connections[i].sessionsecret_key,
                                           c->crypto_connections[i].shared_key);
                        c->crypto_connections[i].status =
                            CRYPTO_CONN_ESTABLISHED; /* Connection status needs to be 3 for write_cryptpacket() to work. */
                        write_cryptpacket(c, i, ((uint8_t *)&zero), sizeof(zero));
                        c->crypto_connections[i].status = CRYPTO_CONN_NOT_CONFIRMED; /* Set it to its proper value right after. */
                    } else {
                        /* This should not happen, timeout the connection if it does. */
                        c->crypto_connections[i].status = CRYPTO_CONN_TIMED_OUT;
                    }
                } else {
                    /* This should not happen, timeout the connection if it does. */
                    c->crypto_connections[i].status = CRYPTO_CONN_TIMED_OUT;
                }
            } else if (id_packet(c->lossless_udp,
                                 c->crypto_connections[i].number) != (uint8_t)~0) {
                /* This should not happen, timeout the connection if it does. */
                c->crypto_connections[i].status = CRYPTO_CONN_TIMED_OUT;
            }
        }

        if (c->crypto_connections[i].status == CRYPTO_CONN_NOT_CONFIRMED) {
            if (id_packet(c->lossless_udp, c->crypto_connections[i].number) == 3) {
                uint8_t temp_data[MAX_DATA_SIZE];
                uint8_t data[MAX_DATA_SIZE];
                int length = read_packet(c->lossless_udp, c->crypto_connections[i].number, temp_data);
                int len = decrypt_data(c->crypto_connections[i].peersessionpublic_key,
                                       c->crypto_connections[i].sessionsecret_key,
                                       c->crypto_connections[i].recv_nonce, temp_data + 1, length - 1, data);
                uint32_t zero = 0;

                if (len == sizeof(uint32_t) && memcmp(((uint8_t *)&zero), data, sizeof(uint32_t)) == 0) {
                    increment_nonce(c->crypto_connections[i].recv_nonce);
                    encrypt_precompute(c->crypto_connections[i].peersessionpublic_key,
                                       c->crypto_connections[i].sessionsecret_key,
                                       c->crypto_connections[i].shared_key);
                    c->crypto_connections[i].status = CRYPTO_CONN_ESTABLISHED;
                    c->crypto_connections[i].timeout = ~0;
                    /* Connection is accepted. */
                    confirm_connection(c->lossless_udp, c->crypto_connections[i].number);
                } else {
                    /* This should not happen, timeout the connection if it does. */
                    c->crypto_connections[i].status = CRYPTO_CONN_TIMED_OUT;
                }
            } else if (id_packet(c->lossless_udp, c->crypto_connections[i].number) != (uint8_t)~0) {
                /* This should not happen, timeout the connection if it does. */
                c->crypto_connections[i].status = CRYPTO_CONN_TIMED_OUT;
            }
        }

        if (temp_time > c->crypto_connections[i].timeout) {
            c->crypto_connections[i].status = CRYPTO_CONN_TIMED_OUT;
        }
    }
}

/* Run this to (re)initialize net_crypto.
 * Sets all the global connection variables to their default values.
 */
Net_Crypto *new_net_crypto(Networking_Core *net)
{
    unix_time_update();

    if (net == NULL)
        return NULL;

    Net_Crypto *temp = calloc(1, sizeof(Net_Crypto));

    if (temp == NULL)
        return NULL;

    temp->lossless_udp = new_lossless_udp(net);

    if (temp->lossless_udp == NULL) {
        free(temp);
        return NULL;
    }

    new_keys(temp);
    return temp;
}

void init_cryptopackets(void *dht)
{
    DHT *s_dht = dht;
    networking_registerhandler(s_dht->c->lossless_udp->net, NET_PACKET_CRYPTO, &cryptopacket_handle, s_dht);
}

static void kill_timedout(Net_Crypto *c)
{
    uint32_t i;

    for (i = 0; i < c->crypto_connections_length; ++i) {
        if (c->crypto_connections[i].status != CRYPTO_CONN_NO_CONNECTION
                && is_connected(c->lossless_udp, c->crypto_connections[i].number) == LUDP_TIMED_OUT)
            c->crypto_connections[i].status = CRYPTO_CONN_TIMED_OUT;
    }
}

/* Main loop. */
void do_net_crypto(Net_Crypto *c)
{
    unix_time_update();
    do_lossless_udp(c->lossless_udp);
    kill_timedout(c);
    receive_crypto(c);
}

void kill_net_crypto(Net_Crypto *c)
{
    uint32_t i;

    for (i = 0; i < c->crypto_connections_length; ++i) {
        crypto_kill(c, i);
    }

    kill_lossless_udp(c->lossless_udp);
    memset(c, 0, sizeof(Net_Crypto));
    free(c);
}
