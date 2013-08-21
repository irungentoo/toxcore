/* Lossless_UDP.c
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

/*
 * TODO: clean this file a bit.
 * There are a couple of useless variables to get rid of.
 */

#include "Lossless_UDP.h"


/* Functions */

/*
 * Get connection id from IP_Port
 * Return -1 if there are no connections like we are looking for
 * Return id if it found it
 */
int getconnection_id(Lossless_UDP *ludp, IP_Port ip_port)
{
    uint32_t i;

    for (i = 0; i < ludp->connections_length; ++i) {
        if (ludp->connections[i].ip_port.ip.i == ip_port.ip.i &&
                ludp->connections[i].ip_port.port == ip_port.port &&
                ludp->connections[i].status > 0)
            return i;
    }

    return -1;
}


/*
 * Generate a handshake_id which depends on the ip_port.
 * This function will always give one unique handshake_id per ip_port.
 *
 * TODO: make this better
 */
static uint32_t handshake_id(Lossless_UDP *ludp, IP_Port source)
{
    uint32_t id = 0, i;

    for (i = 0; i < 6; ++i) {
        if (ludp->randtable[i][((uint8_t *)&source)[i]] == 0)
            ludp->randtable[i][((uint8_t *)&source)[i]] = random_int();

        id ^= ludp->randtable[i][((uint8_t *)&source)[i]];
    }

    if (id == 0) /* id can't be zero */
        id = 1;

    return id;
}

/*
 * Change the hanshake id associated with that ip_port
 *
 * TODO: make this better
 */
static void change_handshake(Lossless_UDP *ludp, IP_Port source)
{
    uint8_t rand = random_int() % 4;
    ludp->randtable[rand][((uint8_t *)&source)[rand]] = random_int();
}

/*
 * Initialize a new connection to ip_port
 * Returns an integer corresponding to the connection idt
 * Return -1 if it could not initialize the connectiont
 * If there already was an existing connection to that ip_port return its number.
 */
int new_connection(Lossless_UDP *ludp, IP_Port ip_port)
{
    int connect = getconnection_id(ludp, ip_port);

    if (connect != -1)
        return connect;

    if (ludp->connections_number == ludp->connections_length) {
        Connection *temp;
        temp = realloc(ludp->connections, sizeof(Connection) * (ludp->connections_length + 1));

        if (temp == NULL)
            return -1;

        memset(&temp[ludp->connections_length], 0, sizeof(Connection));
        ++ludp->connections_length;
        ludp->connections = temp;
    }

    uint32_t i;

    for (i = 0; i < ludp->connections_length; ++i) {
        if (ludp->connections[i].status == 0) {
            memset(&ludp->connections[i], 0, sizeof(Connection));
            uint32_t handshake_id1 = handshake_id(ludp, ip_port);

            ludp->connections[i] = (Connection) {
                .ip_port            = ip_port,
                 .status             = 1,
                  .inbound            = 0,
                   .handshake_id1      = handshake_id1,
                    .sent_packetnum     = handshake_id1,
                     .sendbuff_packetnum = handshake_id1,
                      .successful_sent    = handshake_id1,
                       .SYNC_rate          = SYNC_RATE,
                        .data_rate          = DATA_SYNC_RATE,
                         .last_recvSYNC      = current_time(),
                          .last_sent          = current_time(),
                           .killat             = ~0,
                            .send_counter       = 0,
                             /* add randomness to timeout to prevent connections getting stuck in a loop. */
                             .timeout            = CONNEXION_TIMEOUT + rand() % CONNEXION_TIMEOUT
            };
            ++ludp->connections_number;

            return i;
        }
    }

    return -1;
}

/*
 * Initialize a new inbound connection from ip_port
 * Returns an integer corresponding to the connection id.
 * Return -1 if it could not initialize the connection.
 */
static int new_inconnection(Lossless_UDP *ludp, IP_Port ip_port)
{
    if (getconnection_id(ludp, ip_port) != -1)
        return -1;

    if (ludp->connections_number == ludp->connections_length) {
        Connection *temp;
        temp = realloc(ludp->connections, sizeof(Connection) * (ludp->connections_length + 1));

        if (temp == NULL)
            return -1;

        memset(&temp[ludp->connections_length], 0, sizeof(Connection));
        ++ludp->connections_length;
        ludp->connections = temp;
    }

    uint32_t i;

    for (i = 0; i < ludp->connections_length; ++i) {
        if (ludp->connections[i].status == 0) {
            memset(&ludp->connections[i], 0, sizeof(Connection));
            uint64_t timeout = CONNEXION_TIMEOUT + rand() % CONNEXION_TIMEOUT;

            ludp->connections[i] = (Connection) {
                .ip_port       = ip_port,
                 .status        = 2,
                  .inbound       = 2,
                   .SYNC_rate     = SYNC_RATE,
                    .data_rate     = DATA_SYNC_RATE,
                     .last_recvSYNC = current_time(),
                      .last_sent     = current_time(),
                       .send_counter  = 127,

                        /* add randomness to timeout to prevent connections getting stuck in a loop. */
                        .timeout       = timeout,

                         /* if this connection isn't handled within the timeout kill it. */
                         .killat        = current_time() + 1000000UL * timeout
            };
            ++ludp->connections_number;
            return i;
        }
    }

    return -1;
}

/*
 * Returns an integer corresponding to the next connection in our incoming connection list.
 * Return -1 if there are no new incoming connections in the list.
 */
int incoming_connection(Lossless_UDP *ludp)
{
    uint32_t i;

    for (i = 0; i < ludp->connections_length; ++i) {
        if (ludp->connections[i].inbound == 2) {
            ludp->connections[i].inbound = 1;
            return i;
        }
    }

    return -1;
}

/* Try to free some memory from the connections array. */
static void free_connections(Lossless_UDP *ludp)
{
    uint32_t i;

    for (i = ludp->connections_length; i != 0; --i)
        if (ludp->connections[i - 1].status != 0)
            break;

    if (ludp->connections_length == i)
        return;

    if (i == 0) {
        free(ludp->connections);
        ludp->connections = NULL;
        ludp->connections_length = i;
        return;
    }

    Connection *temp;
    temp = realloc(ludp->connections, sizeof(Connection) * i);

    if (temp == NULL && i != 0)
        return;

    ludp->connections = temp;
    ludp->connections_length = i;
}

/*
 * Return -1 if it could not kill the connection.
 * Return 0 if killed successfully
 */
int kill_connection(Lossless_UDP *ludp, int connection_id)
{
    if (connection_id >= 0 && connection_id < ludp->connections_length) {
        if (ludp->connections[connection_id].status > 0) {
            ludp->connections[connection_id].status = 0;
            change_handshake(ludp, ludp->connections[connection_id].ip_port);
            --ludp->connections_number;
            free_connections(ludp);
            return 0;
        }
    }

    return -1;
}

/*
 * Kill connection in seconds.
 * Return -1 if it can not kill the connection.
 * Return 0 if it will kill it.
 */
int kill_connection_in(Lossless_UDP *ludp, int connection_id, uint32_t seconds)
{
    if (connection_id >= 0 && connection_id < ludp->connections_length) {
        if (ludp->connections[connection_id].status > 0) {
            ludp->connections[connection_id].killat = current_time() + 1000000UL * seconds;
            return 0;
        }
    }

    return -1;
}

/*
 * Check if connection is connected:
 * Return 0 no.
 * Return 1 if attempting handshake.
 * Return 2 if handshake is done.
 * Return 3 if fully connected.
 * Return 4 if timed out and waiting to be killed.
 */
int is_connected(Lossless_UDP *ludp, int connection_id)
{
    if (connection_id >= 0 && connection_id < ludp->connections_length)
        return ludp->connections[connection_id].status;

    return 0;
}

/* returns the ip_port of the corresponding connection. */
IP_Port connection_ip(Lossless_UDP *ludp, int connection_id)
{
    if (connection_id >= 0 && connection_id < ludp->connections_length)
        return ludp->connections[connection_id].ip_port;

    IP_Port zero = {{{0}}, 0};
    return zero;
}

/* returns the number of packets in the queue waiting to be successfully sent. */
uint32_t sendqueue(Lossless_UDP *ludp, int connection_id)
{
    if (connection_id < 0 || connection_id >= ludp->connections_length)
        return 0;

    return ludp->connections[connection_id].sendbuff_packetnum - ludp->connections[connection_id].successful_sent;
}

/* returns the number of packets in the queue waiting to be successfully read with read_packet(...) */
uint32_t recvqueue(Lossless_UDP *ludp, int connection_id)
{
    if (connection_id < 0 || connection_id >= ludp->connections_length)
        return 0;

    return ludp->connections[connection_id].recv_packetnum - ludp->connections[connection_id].successful_read;
}

/* returns the id of the next packet in the queue
   return -1 if no packet in queue */
char id_packet(Lossless_UDP *ludp, int connection_id)
{
    if (connection_id < 0 || connection_id >= ludp->connections_length)
        return -1;

    if (recvqueue(ludp, connection_id) != 0 && ludp->connections[connection_id].status != 0)
        return ludp->connections[connection_id].recvbuffer[ludp->connections[connection_id].successful_read %
                MAX_QUEUE_NUM].data[0];

    return -1;
}

/* return 0 if there is no received data in the buffer.
   return length of received packet if successful */
int read_packet(Lossless_UDP *ludp, int connection_id, uint8_t *data)
{
    if (recvqueue(ludp, connection_id) != 0) {
        uint16_t index = ludp->connections[connection_id].successful_read % MAX_QUEUE_NUM;
        uint16_t size  = ludp->connections[connection_id].recvbuffer[index].size;
        memcpy(data, ludp->connections[connection_id].recvbuffer[index].data, size);
        ++ludp->connections[connection_id].successful_read;
        ludp->connections[connection_id].recvbuffer[index].size = 0;
        return size;
    }

    return 0;
}

/*
 * Return 0 if data could not be put in packet queue
 * Return 1 if data was put into the queue
 */
int write_packet(Lossless_UDP *ludp, int connection_id, uint8_t *data, uint32_t length)
{
    if (length > MAX_DATA_SIZE || length == 0)
        return 0;

    if (sendqueue(ludp, connection_id) <  BUFFER_PACKET_NUM) {
        uint32_t index = ludp->connections[connection_id].sendbuff_packetnum % MAX_QUEUE_NUM;
        memcpy(ludp->connections[connection_id].sendbuffer[index].data, data, length);
        ludp->connections[connection_id].sendbuffer[index].size = length;
        ludp->connections[connection_id].sendbuff_packetnum++;
        return 1;
    }

    return 0;
}

/* put the packet numbers the we are missing in requested and return the number */
uint32_t missing_packets(Lossless_UDP *ludp, int connection_id, uint32_t *requested)
{
    uint32_t number = 0;
    uint32_t i;
    uint32_t temp;

    /* don't request packets if the buffer is full. */
    if (recvqueue(ludp, connection_id) >= (BUFFER_PACKET_NUM - 1))
        return 0;

    for (i = ludp->connections[connection_id].recv_packetnum; i != ludp->connections[connection_id].osent_packetnum; i++) {
        if (ludp->connections[connection_id].recvbuffer[i % MAX_QUEUE_NUM].size == 0) {
            temp = htonl(i);
            memcpy(requested + number, &temp, 4);
            ++number;
        }
    }

    if (number == 0)
        ludp->connections[connection_id].recv_packetnum = ludp->connections[connection_id].osent_packetnum;

    return number;
}

/*
 * BEGIN Packet sending functions
 * One per packet type.
 * see http://wiki.tox.im/index.php/Lossless_UDP for more information.
 */

static int send_handshake(Lossless_UDP *ludp, IP_Port ip_port, uint32_t handshake_id1, uint32_t handshake_id2)
{
    uint8_t packet[1 + 4 + 4];
    uint32_t temp;

    packet[0] = NET_PACKET_HANDSHAKE;
    temp = htonl(handshake_id1);
    memcpy(packet + 1, &temp, 4);
    temp = htonl(handshake_id2);
    memcpy(packet + 5, &temp, 4);

    return sendpacket(ludp->net->sock, ip_port, packet, sizeof(packet));
}

static int send_SYNC(Lossless_UDP *ludp, uint32_t connection_id)
{
    uint8_t packet[(BUFFER_PACKET_NUM * 4 + 4 + 4 + 2)];
    uint16_t index = 0;

    IP_Port ip_port         = ludp->connections[connection_id].ip_port;
    uint8_t counter         = ludp->connections[connection_id].send_counter;
    uint32_t recv_packetnum = htonl(ludp->connections[connection_id].recv_packetnum);
    uint32_t sent_packetnum = htonl(ludp->connections[connection_id].sent_packetnum);

    uint32_t requested[BUFFER_PACKET_NUM];
    uint32_t number         = missing_packets(ludp, connection_id, requested);

    packet[0] = NET_PACKET_SYNC;
    index += 1;
    memcpy(packet + index, &counter, 1);
    index += 1;
    memcpy(packet + index, &recv_packetnum, 4);
    index += 4;
    memcpy(packet + index, &sent_packetnum, 4);
    index += 4;
    memcpy(packet + index, requested, 4 * number);

    return sendpacket(ludp->net->sock, ip_port, packet, (number * 4 + 4 + 4 + 2));

}

static int send_data_packet(Lossless_UDP *ludp, uint32_t connection_id, uint32_t packet_num)
{
    uint32_t index = packet_num % MAX_QUEUE_NUM;
    uint32_t temp;
    uint8_t packet[1 + 4 + MAX_DATA_SIZE];
    packet[0] = NET_PACKET_DATA;
    temp = htonl(packet_num);
    memcpy(packet + 1, &temp, 4);
    memcpy(packet + 5, ludp->connections[connection_id].sendbuffer[index].data,
           ludp->connections[connection_id].sendbuffer[index].size);
    return sendpacket(ludp->net->sock, ludp->connections[connection_id].ip_port, packet,
                      1 + 4 + ludp->connections[connection_id].sendbuffer[index].size);
}

/* sends 1 data packet */
static int send_DATA(Lossless_UDP *ludp, uint32_t connection_id)
{
    int ret;
    uint32_t buffer[BUFFER_PACKET_NUM];

    if (ludp->connections[connection_id].num_req_paquets > 0) {
        ret = send_data_packet(ludp, connection_id, ludp->connections[connection_id].req_packets[0]);
        ludp->connections[connection_id].num_req_paquets--;
        memcpy(buffer, ludp->connections[connection_id].req_packets + 1, ludp->connections[connection_id].num_req_paquets * 4);
        memcpy(ludp->connections[connection_id].req_packets, buffer, ludp->connections[connection_id].num_req_paquets * 4);
        return ret;
    }

    if (ludp->connections[connection_id].sendbuff_packetnum != ludp->connections[connection_id].sent_packetnum) {
        ret = send_data_packet(ludp, connection_id, ludp->connections[connection_id].sent_packetnum);
        ludp->connections[connection_id].sent_packetnum++;
        return ret;
    }

    return 0;
}

/*
 * END of packet sending functions
 *
 *
 * BEGIN Packet handling functions
 * One to handle each type of packets we receive
 */


/* Return 0 if handled correctly, 1 if packet is bad. */
static int handle_handshake(void *object, IP_Port source, uint8_t *packet, uint32_t length)
{
    Lossless_UDP *ludp = object;

    if (length != (1 + 4 + 4))
        return 1;

    uint32_t temp;
    uint32_t handshake_id1, handshake_id2;

    int connection = getconnection_id(ludp, source);
    memcpy(&temp, packet + 1, 4);
    handshake_id1 = ntohl(temp);
    memcpy(&temp, packet + 5, 4);
    handshake_id2 = ntohl(temp);

    if (handshake_id2 == 0 && is_connected(ludp, connection) < 3) {
        send_handshake(ludp, source, handshake_id(ludp, source), handshake_id1);
        return 0;
    }

    if (is_connected(ludp, connection) != 1)
        return 1;

    /* if handshake_id2 is what we sent previously as handshake_id1 */
    if (handshake_id2 == ludp->connections[connection].handshake_id1) {
        ludp->connections[connection].status = 2;
        /* NOTE: is this necessary?
        ludp->connections[connection].handshake_id2 = handshake_id1; */
        ludp->connections[connection].orecv_packetnum = handshake_id2;
        ludp->connections[connection].osent_packetnum = handshake_id1;
        ludp->connections[connection].recv_packetnum  = handshake_id1;
        ludp->connections[connection].successful_read = handshake_id1;
    }

    return 0;
}

/* returns 1 if sync packet is valid 0 if not. */
static int SYNC_valid(uint32_t length)
{
    if (length < 4 + 4 + 2)
        return 0;

    if (length > (BUFFER_PACKET_NUM * 4 + 4 + 4 + 2) ||
            ((length - 4 - 4 - 2) % 4) != 0)
        return 0;

    return 1;
}

/* case 1 in handle_SYNC: */
static int handle_SYNC1(Lossless_UDP *ludp, IP_Port source, uint32_t recv_packetnum, uint32_t sent_packetnum)
{
    if (handshake_id(ludp, source) == recv_packetnum) {
        int x = new_inconnection(ludp, source);

        if (x != -1) {
            ludp->connections[x].orecv_packetnum    = recv_packetnum;
            ludp->connections[x].sent_packetnum     = recv_packetnum;
            ludp->connections[x].sendbuff_packetnum = recv_packetnum;
            ludp->connections[x].successful_sent    = recv_packetnum;
            ludp->connections[x].osent_packetnum    = sent_packetnum;
            ludp->connections[x].recv_packetnum     = sent_packetnum;
            ludp->connections[x].successful_read    = sent_packetnum;

            return x;
        }
    }

    return -1;
}

/* case 2 in handle_SYNC: */
static int handle_SYNC2(Lossless_UDP *ludp, int connection_id, uint8_t counter, uint32_t recv_packetnum,
                        uint32_t sent_packetnum)
{
    if (recv_packetnum == ludp->connections[connection_id].orecv_packetnum) {
        /* && sent_packetnum == ludp->connections[connection_id].osent_packetnum) */
        ludp->connections[connection_id].status =  3;
        ludp->connections[connection_id].recv_counter = counter;
        ++ludp->connections[connection_id].send_counter;
        send_SYNC(ludp, connection_id);
        return 0;
    }

    return 1;
}
/* case 3 in handle_SYNC: */
static int handle_SYNC3(Lossless_UDP *ludp, int connection_id, uint8_t counter, uint32_t recv_packetnum,
                        uint32_t sent_packetnum,
                        uint32_t  *req_packets,
                        uint16_t number)
{
    uint8_t comp_counter = (counter - ludp->connections[connection_id].recv_counter );
    uint32_t i, temp;
    /* uint32_t comp_1 = (recv_packetnum - ludp->connections[connection_id].successful_sent);
       uint32_t comp_2 = (sent_packetnum - ludp->connections[connection_id].successful_read); */
    uint32_t comp_1 = (recv_packetnum - ludp->connections[connection_id].orecv_packetnum);
    uint32_t comp_2 = (sent_packetnum - ludp->connections[connection_id].osent_packetnum);

    /* packet valid */
    if (comp_1 <= BUFFER_PACKET_NUM &&
            comp_2 <= BUFFER_PACKET_NUM &&
            comp_counter < 10 && comp_counter != 0) {

        ludp->connections[connection_id].orecv_packetnum = recv_packetnum;
        ludp->connections[connection_id].osent_packetnum = sent_packetnum;
        ludp->connections[connection_id].successful_sent = recv_packetnum;
        ludp->connections[connection_id].last_recvSYNC   = current_time();
        ludp->connections[connection_id].recv_counter    = counter;

        ++ludp->connections[connection_id].send_counter;

        for (i = 0; i < number; ++i) {
            temp = ntohl(req_packets[i]);
            memcpy(ludp->connections[connection_id].req_packets + i, &temp, 4 * number);
        }

        ludp->connections[connection_id].num_req_paquets = number;
        return 0;
    }

    return 1;
}

static int handle_SYNC(void *object, IP_Port source, uint8_t *packet, uint32_t length)
{
    Lossless_UDP *ludp = object;

    if (!SYNC_valid(length))
        return 1;

    int connection = getconnection_id(ludp, source);
    uint8_t counter;
    uint32_t temp;
    uint32_t recv_packetnum, sent_packetnum;
    uint32_t req_packets[BUFFER_PACKET_NUM];
    uint16_t number = (length - 4 - 4 - 2) / 4;

    memcpy(&counter, packet + 1, 1);
    memcpy(&temp, packet + 2, 4);
    recv_packetnum = ntohl(temp);
    memcpy(&temp, packet + 6,  4);
    sent_packetnum = ntohl(temp);

    if (number != 0)
        memcpy(req_packets, packet + 10,  4 * number);

    if (connection == -1)
        return handle_SYNC1(ludp, source, recv_packetnum, sent_packetnum);

    if (ludp->connections[connection].status ==  2)
        return handle_SYNC2(ludp, connection, counter,
                            recv_packetnum, sent_packetnum);

    if (ludp->connections[connection].status ==  3)
        return handle_SYNC3(ludp, connection, counter, recv_packetnum,
                            sent_packetnum, req_packets, number);

    return 0;
}

/*
 * Add a packet to the received buffer and set the recv_packetnum of the
 * connection to its proper value. Return 1 if data was too big, 0 if not.
 */
static int add_recv(Lossless_UDP *ludp, int connection_id, uint32_t data_num, uint8_t *data, uint16_t size)
{
    if (size > MAX_DATA_SIZE)
        return 1;

    uint32_t i;
    uint32_t maxnum = ludp->connections[connection_id].successful_read + BUFFER_PACKET_NUM;
    uint32_t sent_packet = data_num - ludp->connections[connection_id].osent_packetnum;

    for (i = ludp->connections[connection_id].recv_packetnum; i != maxnum; ++i) {
        if (i == data_num) {
            memcpy(ludp->connections[connection_id].recvbuffer[i % MAX_QUEUE_NUM].data, data, size);

            ludp->connections[connection_id].recvbuffer[i % MAX_QUEUE_NUM].size = size;
            ludp->connections[connection_id].last_recvdata = current_time();

            if (sent_packet < BUFFER_PACKET_NUM) {
                ludp->connections[connection_id].osent_packetnum = data_num;
            }

            break;
        }
    }

    for (i = ludp->connections[connection_id].recv_packetnum; i != maxnum; ++i) {
        if (ludp->connections[connection_id].recvbuffer[i % MAX_QUEUE_NUM].size != 0)
            ludp->connections[connection_id].recv_packetnum = i;
        else
            break;
    }

    return 0;
}

static int handle_data(void *object, IP_Port source, uint8_t *packet, uint32_t length)
{
    Lossless_UDP *ludp = object;
    int connection = getconnection_id(ludp, source);

    if (connection == -1)
        return 1;

    /* Drop the data packet if connection is not connected. */
    if (ludp->connections[connection].status != 3)
        return 1;

    if (length > 1 + 4 + MAX_DATA_SIZE || length < 1 + 4 + 1)
        return 1;

    uint32_t temp;
    uint32_t number;
    uint16_t size = length - 1 - 4;

    memcpy(&temp, packet + 1, 4);
    number = ntohl(temp);

    return add_recv(ludp, connection, number, packet + 5, size);
}

/*
 * END of packet handling functions
 */

Lossless_UDP *new_lossless_udp(Networking_Core *net)
{
    if (net == NULL)
        return NULL;

    Lossless_UDP *temp = calloc(1, sizeof(Lossless_UDP));

    if (temp == NULL)
        return NULL;

    temp->net = net;
    networking_registerhandler(net, NET_PACKET_HANDSHAKE, &handle_handshake, temp);
    networking_registerhandler(net, NET_PACKET_SYNC, &handle_SYNC, temp);
    networking_registerhandler(net, NET_PACKET_DATA, &handle_data, temp);
    return temp;
}

/*
 * Send handshake requests
 * handshake packets are sent at the same rate as SYNC packets
 */
static void do_new(Lossless_UDP *ludp)
{
    uint32_t i;
    uint64_t temp_time = current_time();

    for (i = 0; i < ludp->connections_length; ++i) {
        if (ludp->connections[i].status == 1)
            if ((ludp->connections[i].last_sent + (1000000UL / ludp->connections[i].SYNC_rate)) <= temp_time) {
                send_handshake(ludp, ludp->connections[i].ip_port, ludp->connections[i].handshake_id1, 0);
                ludp->connections[i].last_sent = temp_time;
            }

        /* kill all timed out connections */
        if (ludp->connections[i].status > 0 &&
                (ludp->connections[i].last_recvSYNC + ludp->connections[i].timeout * 1000000UL) < temp_time &&
                ludp->connections[i].status != 4) {
            ludp->connections[i].status = 4;
            /* kill_connection(i); */
        }

        if (ludp->connections[i].status > 0 && ludp->connections[i].killat < temp_time)
            kill_connection(ludp, i);
    }
}

static void do_SYNC(Lossless_UDP *ludp)
{
    uint32_t i;
    uint64_t temp_time = current_time();

    for (i = 0; i < ludp->connections_length; ++i) {
        if (ludp->connections[i].status == 2 || ludp->connections[i].status == 3)
            if ((ludp->connections[i].last_SYNC + (1000000UL / ludp->connections[i].SYNC_rate)) <= temp_time) {
                send_SYNC(ludp, i);
                ludp->connections[i].last_SYNC = temp_time;
            }
    }
}

static void do_data(Lossless_UDP *ludp)
{
    uint32_t i;
    uint64_t j;
    uint64_t temp_time = current_time();

    for (i = 0; i < ludp->connections_length; ++i)
        if (ludp->connections[i].status == 3 && sendqueue(ludp, i) != 0)
            if ((ludp->connections[i].last_sent + (1000000UL / ludp->connections[i].data_rate)) <= temp_time) {
                for (j = ludp->connections[i].last_sent; j < temp_time; j +=  (1000000UL / ludp->connections[i].data_rate))
                    send_DATA(ludp, i);

                ludp->connections[i].last_sent = temp_time;
            }
}

#define MAX_SYNC_RATE 10

/*
 * Automatically adjusts send rates of packets for optimal transmission.
 *
 * TODO: flow control.
 */
static void adjust_rates(Lossless_UDP *ludp)
{
    uint32_t i;
    uint64_t temp_time = current_time();

    for (i = 0; i < ludp->connections_length; ++i) {
        if (ludp->connections[i].status == 1 || ludp->connections[i].status == 2)
            ludp->connections[i].SYNC_rate = MAX_SYNC_RATE;

        if (ludp->connections[i].status == 3) {
            if (sendqueue(ludp, i) != 0) {
                ludp->connections[i].data_rate = (BUFFER_PACKET_NUM - ludp->connections[i].num_req_paquets) * MAX_SYNC_RATE;
                ludp->connections[i].SYNC_rate = MAX_SYNC_RATE;
            } else if (ludp->connections[i].last_recvdata + 1000000UL > temp_time)
                ludp->connections[i].SYNC_rate = MAX_SYNC_RATE;
            else
                ludp->connections[i].SYNC_rate = SYNC_RATE;
        }
    }
}

/* Call this function a couple times per second It's the main loop. */
void do_lossless_udp(Lossless_UDP *ludp)
{
    do_new(ludp);
    do_SYNC(ludp);
    do_data(ludp);
    adjust_rates(ludp);
}

void kill_lossless_udp(Lossless_UDP *ludp)
{
    free(ludp->connections);
    free(ludp);
}
