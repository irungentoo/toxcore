/* SPDX-License-Identifier: GPL-3.0-or-later
 * Copyright © 2016-2018 The TokTok team.
 * Copyright © 2014 Tox project.
 */

#include "TCP_common.h"

#include <stdlib.h>
#include <string.h>

void wipe_priority_list(TCP_Priority_List *p)
{
    while (p) {
        TCP_Priority_List *pp = p;
        p = p->next;
        free(pp);
    }
}

/** return 0 if pending data was sent completely
 * return -1 if it wasn't
 */
int send_pending_data_nonpriority(TCP_Connection *con)
{
    if (con->last_packet_length == 0) {
        return 0;
    }

    const uint16_t left = con->last_packet_length - con->last_packet_sent;
    const int len = net_send(con->sock, con->last_packet + con->last_packet_sent, left);

    if (len <= 0) {
        return -1;
    }

    if (len == left) {
        con->last_packet_length = 0;
        con->last_packet_sent = 0;
        return 0;
    }

    con->last_packet_sent += len;
    return -1;
}

/** return 0 if pending data was sent completely
 * return -1 if it wasn't
 */
int send_pending_data(TCP_Connection *con)
{
    /* finish sending current non-priority packet */
    if (send_pending_data_nonpriority(con) == -1) {
        return -1;
    }

    TCP_Priority_List *p = con->priority_queue_start;

    while (p) {
        const uint16_t left = p->size - p->sent;
        const int len = net_send(con->sock, p->data + p->sent, left);

        if (len != left) {
            if (len > 0) {
                p->sent += len;
            }

            break;
        }

        TCP_Priority_List *pp = p;
        p = p->next;
        free(pp);
    }

    con->priority_queue_start = p;

    if (!p) {
        con->priority_queue_end = nullptr;
        return 0;
    }

    return -1;
}

/** return 0 on failure (only if calloc fails)
 * return 1 on success
 */
bool add_priority(TCP_Connection *con, const uint8_t *packet, uint16_t size, uint16_t sent)
{
    TCP_Priority_List *p = con->priority_queue_end;
    TCP_Priority_List *new_list = (TCP_Priority_List *)calloc(1, sizeof(TCP_Priority_List) + size);

    if (!new_list) {
        return 0;
    }

    new_list->next = nullptr;
    new_list->size = size;
    new_list->sent = sent;
    memcpy(new_list->data, packet, size);

    if (p) {
        p->next = new_list;
    } else {
        con->priority_queue_start = new_list;
    }

    con->priority_queue_end = new_list;
    return 1;
}

/** return 1 on success.
 * return 0 if could not send packet.
 * return -1 on failure (connection must be killed).
 */
int write_packet_TCP_secure_connection(TCP_Connection *con, const uint8_t *data, uint16_t length, bool priority)
{
    if (length + CRYPTO_MAC_SIZE > MAX_PACKET_SIZE) {
        return -1;
    }

    bool sendpriority = 1;

    if (send_pending_data(con) == -1) {
        if (priority) {
            sendpriority = 0;
        } else {
            return 0;
        }
    }

    VLA(uint8_t, packet, sizeof(uint16_t) + length + CRYPTO_MAC_SIZE);

    uint16_t c_length = net_htons(length + CRYPTO_MAC_SIZE);
    memcpy(packet, &c_length, sizeof(uint16_t));
    int len = encrypt_data_symmetric(con->shared_key, con->sent_nonce, data, length, packet + sizeof(uint16_t));

    if ((unsigned int)len != (SIZEOF_VLA(packet) - sizeof(uint16_t))) {
        return -1;
    }

    if (priority) {
        len = sendpriority ? net_send(con->sock, packet, SIZEOF_VLA(packet)) : 0;

        if (len <= 0) {
            len = 0;
        }

        increment_nonce(con->sent_nonce);

        if ((unsigned int)len == SIZEOF_VLA(packet)) {
            return 1;
        }

        return add_priority(con, packet, SIZEOF_VLA(packet), len);
    }

    len = net_send(con->sock, packet, SIZEOF_VLA(packet));

    if (len <= 0) {
        return 0;
    }

    increment_nonce(con->sent_nonce);

    if ((unsigned int)len == SIZEOF_VLA(packet)) {
        return 1;
    }

    memcpy(con->last_packet, packet, SIZEOF_VLA(packet));
    con->last_packet_length = SIZEOF_VLA(packet);
    con->last_packet_sent = len;
    return 1;
}

/** Read length bytes from socket.
 *
 * return length on success
 * return -1 on failure/no data in buffer.
 */
int read_TCP_packet(const Logger *logger, Socket sock, uint8_t *data, uint16_t length)
{
    unsigned int count = net_socket_data_recv_buffer(sock);

    if (count >= length) {
        const int len = net_recv(sock, data, length);

        if (len != length) {
            LOGGER_ERROR(logger, "FAIL recv packet");
            return -1;
        }

        return len;
    }

    return -1;
}

/** Read the next two bytes in TCP stream then convert them to
 * length (host byte order).
 *
 * return length on success
 * return 0 if nothing has been read from socket.
 * return -1 on failure.
 */
static uint16_t read_TCP_length(const Logger *logger, Socket sock)
{
    const unsigned int count = net_socket_data_recv_buffer(sock);

    if (count >= sizeof(uint16_t)) {
        uint16_t length;
        const int len = net_recv(sock, &length, sizeof(uint16_t));

        if (len != sizeof(uint16_t)) {
            LOGGER_ERROR(logger, "FAIL recv packet");
            return 0;
        }

        length = net_ntohs(length);

        if (length > MAX_PACKET_SIZE) {
            return -1;
        }

        return length;
    }

    return 0;
}

/** return length of received packet on success.
 * return 0 if could not read any packet.
 * return -1 on failure (connection must be killed).
 */
int read_packet_TCP_secure_connection(const Logger *logger, Socket sock, uint16_t *next_packet_length,
                                      const uint8_t *shared_key, uint8_t *recv_nonce, uint8_t *data, uint16_t max_len)
{
    if (*next_packet_length == 0) {
        uint16_t len = read_TCP_length(logger, sock);

        if (len == (uint16_t) -1) {
            return -1;
        }

        if (len == 0) {
            return 0;
        }

        *next_packet_length = len;
    }

    if (max_len + CRYPTO_MAC_SIZE < *next_packet_length) {
        return -1;
    }

    VLA(uint8_t, data_encrypted, *next_packet_length);
    int len_packet = read_TCP_packet(logger, sock, data_encrypted, *next_packet_length);

    if (len_packet != *next_packet_length) {
        return 0;
    }

    *next_packet_length = 0;

    int len = decrypt_data_symmetric(shared_key, recv_nonce, data_encrypted, len_packet, data);

    if (len + CRYPTO_MAC_SIZE != len_packet) {
        return -1;
    }

    increment_nonce(recv_nonce);

    return len;
}
