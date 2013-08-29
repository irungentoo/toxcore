/* Lossless_UDP.h
 *
 * An implementation of the Lossless_UDP protocol as seen in http://wiki.tox.im/index.php/Lossless_UDP
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

#ifndef LOSSLESS_UDP_H
#define LOSSLESS_UDP_H

#include "network.h"
#include "misc_tools.h"

#ifdef __cplusplus
extern "C" {
#endif

/* maximum length of the data in the data packets */
#define MAX_DATA_SIZE 1024

/* maximum data packets in sent and receive queues. */
#define MAX_QUEUE_NUM     16

/* maximum number of data packets in the buffer */
#define BUFFER_PACKET_NUM (16-1)

/* timeout per connection is randomly set between CONNEXION_TIMEOUT and 2*CONNEXION_TIMEOUT */
#define CONNEXION_TIMEOUT 5

/* initial amount of sync/hanshake packets to send per second. */
#define SYNC_RATE         2

/* initial send rate of data. */
#define DATA_SYNC_RATE    30

typedef struct {
    uint8_t  data[MAX_DATA_SIZE];
    uint16_t size;
} Data;

typedef struct {
    IP_Port ip_port;

    /*
     * 0 if connection is dead, 1 if attempting handshake,
     * 2 if handshake is done (we start sending SYNC packets)
     * 3 if we are sending SYNC packets and can send data
     * 4 if the connection has timed out.
     */
    uint8_t status;

    /*
     * 1 or 2 if connection was initiated by someone else, 0 if not.
     * 2 if incoming_connection() has not returned it yet, 1 if it has.
     */
    uint8_t inbound;

    uint16_t  SYNC_rate;     /* current SYNC packet send rate packets per second. */
    uint16_t  data_rate;     /* current data packet send rate packets per second. */

    uint64_t  last_SYNC;     /* time our last SYNC packet was sent. */
    uint64_t  last_sent;     /* time our last data or handshake packet was sent. */
    uint64_t  last_recvSYNC; /* time we last received a SYNC packet from the other */
    uint64_t  last_recvdata; /* time we last received a DATA packet from the other */
    uint64_t  killat;        /* time to kill the connection */

    Data      sendbuffer[MAX_QUEUE_NUM]; /* packet send buffer. */
    Data      recvbuffer[MAX_QUEUE_NUM]; /* packet receive buffer. */

    uint32_t  handshake_id1;
    uint32_t  handshake_id2;

    /* number of data packets received (also used as handshake_id1) */
    uint32_t  recv_packetnum;

    /* number of packets received by the other peer */
    uint32_t  orecv_packetnum;

    /* number of data packets sent */
    uint32_t  sent_packetnum;

    /* number of packets sent by the other peer. */
    uint32_t  osent_packetnum;

    /* number of latest packet written onto the sendbuffer */
    uint32_t  sendbuff_packetnum;

    /* we know all packets before that number were successfully sent */
    uint32_t  successful_sent;

    /* packet number of last packet read with the read_packet function */
    uint32_t  successful_read;

    /* list of currently requested packet numbers(by the other person) */
    uint32_t  req_packets[BUFFER_PACKET_NUM];

    /* total number of currently requested packets(by the other person) */
    uint16_t  num_req_paquets;

    uint8_t   recv_counter;
    uint8_t   send_counter;
    uint8_t   timeout; /* connection timeout in seconds. */
} Connection;

typedef struct {
    Networking_Core *net;

    tox_array connections;

    /* table of random numbers used in handshake_id. */
    uint32_t randtable[6][256];

} Lossless_UDP;

/*
 * Initialize a new connection to ip_port
 * Returns an integer corresponding to the connection id.
 * Return -1 if it could not initialize the connection.
 * Return number if there already was an existing connection to that ip_port.
 */
int new_connection(Lossless_UDP *ludp, IP_Port ip_port);

/*
 * Get connection id from IP_Port.
 * Return -1 if there are no connections like we are looking for.
 * Return id if it found it .
 */
int getconnection_id(Lossless_UDP *ludp, IP_Port ip_port);

/*
 * Returns an int corresponding to the next connection in our imcoming connection list
 * Return -1 if there are no new incoming connections in the list.
 */
int incoming_connection(Lossless_UDP *ludp);

/*
 * Return -1 if it could not kill the connection.
 * Return 0 if killed successfully
 */
int kill_connection(Lossless_UDP *ludp, int connection_id);

/*
 * Kill connection in seconds seconds.
 * Return -1 if it can not kill the connection.
 * Return 0 if it will kill it
 */
int kill_connection_in(Lossless_UDP *ludp, int connection_id, uint32_t seconds);

/*
 * Returns the ip_port of the corresponding connection.
 * Return 0 if there is no such connection.
 */
IP_Port connection_ip(Lossless_UDP *ludp, int connection_id);

/*
 * Returns the id of the next packet in the queue
 * Return -1 if no packet in queue
 */
char id_packet(Lossless_UDP *ludp, int connection_id);

/*
 * Return 0 if there is no received data in the buffer.
 * Return length of received packet if successful
 */
int read_packet(Lossless_UDP *ludp, int connection_id, uint8_t *data);

/*
 * Return 0 if data could not be put in packet queue
 * Return 1 if data was put into the queue
 */
int write_packet(Lossless_UDP *ludp, int connection_id, uint8_t *data, uint32_t length);

/* Returns the number of packets in the queue waiting to be successfully sent. */
uint32_t sendqueue(Lossless_UDP *ludp, int connection_id);

/*
 * returns the number of packets in the queue waiting to be successfully
 * read with read_packet(...)
 */
uint32_t recvqueue(Lossless_UDP *ludp, int connection_id);

/* Check if connection is connected:
 * Return 0 no.
 * Return 1 if attempting handshake.
 * Return 2 if handshake is done.
 * Return 3 if fully connected.
 * Return 4 if timed out and wating to be killed.
 */
int is_connected(Lossless_UDP *ludp, int connection_id);

/* Call this function a couple times per second It's the main loop. */
void do_lossless_udp(Lossless_UDP *ludp);

/*
 * This function sets up LosslessUDP packet handling.
 */
Lossless_UDP *new_lossless_udp(Networking_Core *net);

void kill_lossless_udp(Lossless_UDP *ludp);

#ifdef __cplusplus
}
#endif

#endif
