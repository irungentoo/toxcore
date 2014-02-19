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


/* Maximum length of the data in the data packets. */
#define MAX_DATA_SIZE 1024

/* Maximum data packets in sent and receive queues. */
#define MAX_QUEUE_NUM     1024
#define DEFAULT_QUEUE_NUM     4

/* Maximum number of data packets in the buffer. */
#define MAX_REQUESTED_PACKETS 256

/* Timeout per connection is randomly set between CONNECTION_TIMEOUT and 2*CONNECTION_TIMEOUT. */
#define CONNECTION_TIMEOUT 5

/* Initial amount of sync/handshake packets to send per second. */
#define SYNC_RATE         2

/* Initial send rate of data. */
#define DATA_SYNC_RATE    30

typedef struct {
    size_t  data[MAX_DATA_SIZE];
    size_t size;
} Data;

#define LUDP_NO_CONNECTION 0
#define LUDP_HANDSHAKE_SENDING 1
#define LUDP_NOT_CONFIRMED 2
#define LUDP_ESTABLISHED 3
#define LUDP_TIMED_OUT 4

typedef struct {
    IP_Port ip_port;

    /*
     *  return LUDP_NO_CONNECTION if connection is dead.
     *  return LUDP_HANDSHAKE_SENDING if attempting handshake.
     *  return LUDP_NOT_CONFIRMED if handshake is done (we start sending SYNC packets).
     *  return LUDP_ESTABLISHED if we are sending SYNC packets and can send data.
     *  return LUDP_TIMED_OUT if the connection has timed out.
     */
    size_t status;

    /*
     *  return 0 if connection was not initiated by someone else.
     *  return 1 if incoming_connection() has returned.
     *  return 2 if it has not.
     */
    size_t inbound;

    size_t  SYNC_rate;     /* Current SYNC packet send rate packets per second. */
    size_t  data_rate;     /* Current data packet send rate packets per second. */

    size_t  last_SYNC;     /* Time our last SYNC packet was sent. */
    size_t  last_sent;     /* Time our last data or handshake packet was sent. */
    size_t  last_recvSYNC; /* Time we last received a SYNC packet from the other. */
    size_t  last_recvdata; /* Time we last received a DATA packet from the other. */
    size_t  killat;        /* Time to kill the connection. */

    Data      *sendbuffer; /* packet send buffer. */
    size_t  sendbuffer_length;
    Data      *recvbuffer; /* packet receive buffer. */
    size_t  recvbuffer_length;
    size_t  handshake_id1;
    size_t  handshake_id2;

    /* Number of data packets received (also used as handshake_id1). */
    size_t  recv_packetnum;

    /* Number of packets received by the other peer. */
    size_t  orecv_packetnum;

    /* Number of data packets sent. */
    size_t  sent_packetnum;

    /* Number of packets sent by the other peer. */
    size_t  osent_packetnum;

    /* Number of latest packet written onto the sendbuffer. */
    size_t  sendbuff_packetnum;

    /* We know all packets before that number were successfully sent. */
    size_t  successful_sent;

    /* Packet number of last packet read with the read_packet function. */
    size_t  successful_read;

    /* List of currently requested packet numbers(by the other person). */
    size_t  req_packets[MAX_REQUESTED_PACKETS];

    /* Total number of currently requested packets(by the other person). */
    size_t  num_req_paquets;

    size_t   recv_counter;
    size_t   send_counter;
    size_t   timeout; /* connection timeout in seconds. */

    /* Is the connection confirmed or not? 1 if yes, 0 if no */
    size_t   confirmed;
} Connection;

typedef struct {
    Networking_Core *net;

    tox_array connections;

    /* Table of random numbers used in handshake_id. */
    /* IPv6 (16) + port (2)*/
    size_t randtable[18][256];
} Lossless_UDP;

/*
 * Initialize a new connection to ip_port.
 *
 *  return an integer corresponding to the connection id.
 *  return -1 if it could not initialize the connection.
 *  return number if there already was an existing connection to that ip_port.
 */
ptrdiff_t new_connection(Lossless_UDP *ludp, IP_Port ip_port);

/*
 * Get connection id from IP_Port.
 *
 *  return -1 if there are no connections like we are looking for.
 *  return id if it found it .
 */
ptrdiff_t getconnection_id(Lossless_UDP *ludp, IP_Port ip_port);

/*
 *  return an integer corresponding to the next connection in our incoming connection list with at least numpackets in the recieve queue.
 *  return -1 if there are no new incoming connections in the list.
 */
ptrdiff_t incoming_connection(Lossless_UDP *ludp, size_t numpackets);

/*  return -1 if it could not kill the connection.
 *  return 0 if killed successfully.
 */
ptrdiff_t kill_connection(Lossless_UDP *ludp, ptrdiff_t connection_id);

/*
 * timeout connection in seconds seconds.
 *
 *  return -1 if it can not kill the connection.
 *  return 0 if it will kill it.
 */
ptrdiff_t timeout_connection_in(Lossless_UDP *ludp, ptrdiff_t connection_id, size_t seconds);


/* Check if connection is confirmed.
 *
 *  returns 1 if yes.
 *  returns 0 if no.
 */
ptrdiff_t connection_confirmed(Lossless_UDP *ludp, ptrdiff_t connection_id);

/* Confirm an incoming connection.
 * Also disables the auto kill timeout on incomming connections.
 *
 *  return 0 on success
 *  return -1 on failure.
 */
ptrdiff_t confirm_connection(Lossless_UDP *ludp, ptrdiff_t connection_id);

/*  returns the ip_port of the corresponding connection.
 *  return 0 if there is no such connection.
 */
IP_Port connection_ip(Lossless_UDP *ludp, ptrdiff_t connection_id);

/*  returns the id of the next packet in the queue.
 *  return -1 if no packet in queue.
 */
size_t connection_id);

/*  return 0 if there is no received data in the buffer.
 *  return length of received packet if successful.
 */
ptrdiff_t read_packet(Lossless_UDP *ludp, ptrdiff_t connection_id, size_t *data);

/* Like read_packet() but does leaves the queue as is.
 *  return 0 if there is no received data in the buffer.
 *  return length of received packet if successful.
 */
ptrdiff_t read_packet_silent(Lossless_UDP *ludp, ptrdiff_t connection_id, size_t *data);

/* Discard the next packet to be read from the queue
 *  return 0 if success.
 *  return -1 if failure.
 */
ptrdiff_t discard_packet(Lossless_UDP *ludp, ptrdiff_t connection_id);

/* returns the number of packet slots left in the sendbuffer.
 * return 0 if failure.
 */
size_t connection_id);

/*  return 0 if data could not be put in packet queue.
 *  return 1 if data was put into the queue.
 */
ptrdiff_t write_packet(Lossless_UDP *ludp, ptrdiff_t connection_id, size_t length);

/*  return number of packets in the queue waiting to be successfully sent. */
size_t connection_id);

/*  return number of packets in all queues waiting to be successfully sent. */
size_t sendqueue_total(Lossless_UDP *ludp);

/*
 *  return number of packets in the queue waiting to be successfully
 *  read with read_packet(...).
 */
size_t connection_id);

/* Check if connection is connected:
 *
 *  return LUDP_NO_CONNECTION if not.
 *  return LUDP_HANDSHAKE_SENDING if attempting handshake.
 *  return LUDP_NOT_CONFIRMED if handshake is done.
 *  return LUDP_ESTABLISHED if fully connected.
 *  return LUDP_TIMED_OUT if timed out and wating to be killed.
 */
ptrdiff_t is_connected(Lossless_UDP *ludp, ptrdiff_t connection_id);

/* Call this function a couple times per second. It is the main loop. */
void do_lossless_udp(Lossless_UDP *ludp);

/* This function sets up LosslessUDP packet handling. */
Lossless_UDP *new_lossless_udp(Networking_Core *net);

void kill_lossless_udp(Lossless_UDP *ludp);


#endif
