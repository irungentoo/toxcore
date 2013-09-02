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
 * Get connection id from IP_Port.
 *
 * return -1 if there are no connections like we are looking for.
 * return id if it found it.
 */
int getconnection_id(Lossless_UDP *ludp, IP_Port ip_port)
{
    tox_array_for_each(&ludp->connections, Connection, tmp) {
        if (tmp->ip_port.ip.uint32 == ip_port.ip.uint32 &&
                tmp->ip_port.port == ip_port.port &&
                tmp->status > 0) {
            return tmp_i;
        }
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
        if (ludp->randtable[i][source.uint8[i]] == 0)
            ludp->randtable[i][source.uint8[i]] = random_int();

        id ^= ludp->randtable[i][source.uint8[i]];
    }

    /* id can't be zero. */
    if (id == 0)
        id = 1;

    return id;
}

/*
 * Change the handshake id associated with that ip_port.
 *
 * TODO: Make this better
 */
static void change_handshake(Lossless_UDP *ludp, IP_Port source)
{
    uint8_t rand = random_int() % 4;
    ludp->randtable[rand][((uint8_t *)&source)[rand]] = random_int();
}

/*
 * Initialize a new connection to ip_port
 *
 * return an integer corresponding to the connection id.
 * return -1 if it could not initialize the connectiont
 * If there already was an existing connection to that ip_port return its number.
 */
int new_connection(Lossless_UDP *ludp, IP_Port ip_port)
{
    int connection_id = getconnection_id(ludp, ip_port);

    if (connection_id != -1)
        return connection_id;

    tox_array_for_each(&ludp->connections, Connection, tmp) {
        if (tmp->status == 0) {
            connection_id = tmp_i;
            break;
        }
    }

    if (connection_id == -1) {
        if (tox_array_push_ptr(&ludp->connections, 0) == 0)
            return -1;

        connection_id = ludp->connections.len - 1;
    }

    Connection *connection = &tox_array_get(&ludp->connections, connection_id, Connection);

    memset(connection, 0, sizeof(Connection));

    uint32_t handshake_id1 = handshake_id(ludp, ip_port);

    *connection = (Connection) {
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

    return connection_id;
}

/*
 * Initialize a new inbound connection from ip_port.
 *
 *  return an integer corresponding to the connection id.
 *  return -1 if it could not initialize the connection.
 */
static int new_inconnection(Lossless_UDP *ludp, IP_Port ip_port)
{
    if (getconnection_id(ludp, ip_port) != -1)
        return -1; /* TODO: return existing connection instead? */

    int connection_id = -1;
    tox_array_for_each(&ludp->connections, Connection, tmp) {
        if (tmp->status == 0) {
            connection_id = tmp_i;
            break;
        }
    }

    if (connection_id == -1) {
        if (tox_array_push_ptr(&ludp->connections, 0) == 0)
            return -1;

        connection_id = ludp->connections.len - 1;
    }

    Connection *connection = &tox_array_get(&ludp->connections, connection_id, Connection);
    memset(connection, 0, sizeof(Connection));

    uint64_t timeout = CONNEXION_TIMEOUT + rand() % CONNEXION_TIMEOUT;

    *connection = (Connection) {
        .ip_port = ip_port,
         .status = 2,
          .inbound = 2,
           .SYNC_rate = SYNC_RATE,
            .data_rate = DATA_SYNC_RATE,
             .last_recvSYNC = current_time(),
              .last_sent = current_time(),
               .send_counter = 127,

                /* Add randomness to timeout to prevent connections getting stuck in a loop. */
                .timeout = timeout,

                 /* If this connection isn't handled within the timeout kill it. */
                 .killat = current_time() + 1000000UL * timeout
    };

    return connection_id;
}

/*
 *  return an integer corresponding to the next connection in our incoming connection list.
 *  return -1 if there are no new incoming connections in the list.
 */
int incoming_connection(Lossless_UDP *ludp)
{
    tox_array_for_each(&ludp->connections, Connection, tmp) {
        if (tmp->inbound == 2) {
            tmp->inbound = 1;
            return tmp_i;
        }
    }
    return -1;
}
/* Try to free some memory from the connections array. */
static void free_connections(Lossless_UDP *ludp)
{
    uint32_t i;

    for (i = ludp->connections.len; i != 0; --i) {
        Connection *connection = &tox_array_get(&ludp->connections, i, Connection);

        if (connection->status != 0)
            break;
    }

    if (ludp->connections.len == i)
        return;

    return tox_array_pop(&ludp->connections, ludp->connections.len - i);
}
/*  return -1 if it could not kill the connection.
 *  return 0 if killed successfully.
 */
int kill_connection(Lossless_UDP *ludp, int connection_id)
{
    if ((unsigned int)connection_id < ludp->connections.len) {
        Connection *connection = &tox_array_get(&ludp->connections, connection_id, Connection);

        if (connection->status > 0) {
            connection->status = 0;
            change_handshake(ludp, connection->ip_port);
            memset(connection, 0, sizeof(Connection));
            free_connections(ludp);
            return 0;
        }
    }

    return -1;
}

/*
 * Kill connection in seconds.
 *
 *  return -1 if it can not kill the connection.
 *  return 0 if it will kill it.
 */
int kill_connection_in(Lossless_UDP *ludp, int connection_id, uint32_t seconds)
{
    if ((unsigned int)connection_id < ludp->connections.len) {
        Connection *connection = &tox_array_get(&ludp->connections, connection_id, Connection);

        if (connection->status > 0) {
            connection->killat = current_time() + 1000000UL * seconds;
            return 0;
        }
    }

    return -1;
}

/*
 * Check if connection is connected:
 *
 *  return 0 if not.
 *  return 1 if attempting handshake.
 *  return 2 if handshake is done.
 *  return 3 if fully connected.
 *  return 4 if timed out and waiting to be killed.
 */
int is_connected(Lossless_UDP *ludp, int connection_id)
{
    if ((unsigned int)connection_id < ludp->connections.len)
        return tox_array_get(&ludp->connections, connection_id, Connection).status;

    return 0;
}

/*  return the ip_port of the corresponding connection. */
IP_Port connection_ip(Lossless_UDP *ludp, int connection_id)
{
    if ((unsigned int)connection_id < ludp->connections.len)
        return tox_array_get(&ludp->connections, connection_id, Connection).ip_port;

    IP_Port zero = {{{{0}}, 0, 0}};
    return zero;
}

/*  return the number of packets in the queue waiting to be successfully sent. */
uint32_t sendqueue(Lossless_UDP *ludp, int connection_id)
{
    if ((unsigned int)connection_id >= ludp->connections.len)
        return 0;

    Connection *connection = &tox_array_get(&ludp->connections, connection_id, Connection);

    if (connection->status == 0)
        return 0;

    return connection->sendbuff_packetnum - connection->successful_sent;
}

/*  return the number of packets in the queue waiting to be successfully read with read_packet(...). */
uint32_t recvqueue(Lossless_UDP *ludp, int connection_id)
{
    if ((unsigned int)connection_id >= ludp->connections.len)
        return 0;

    Connection *connection = &tox_array_get(&ludp->connections, connection_id, Connection);

    if (connection->status == 0)
        return 0;

    return connection->recv_packetnum - connection->successful_read;
}

/*  return the id of the next packet in the queue.
 *  return -1 if no packet in queue.
 */
char id_packet(Lossless_UDP *ludp, int connection_id)
{
    if (recvqueue(ludp, connection_id) == 0)
        return -1;

    Connection *connection = &tox_array_get(&ludp->connections, connection_id, Connection);

    if (connection->status != 0)
        return connection->recvbuffer[connection->successful_read % MAX_QUEUE_NUM].data[0];

    return -1;
}

/*  return 0 if there is no received data in the buffer.
 *  return length of received packet if successful.
 */
int read_packet(Lossless_UDP *ludp, int connection_id, uint8_t *data)
{
    if (recvqueue(ludp, connection_id) == 0)
        return 0;

    Connection *connection = &tox_array_get(&ludp->connections, connection_id, Connection);

    if (connection->status == 0)
        return 0;

    uint16_t index = connection->successful_read % MAX_QUEUE_NUM;
    uint16_t size  = connection->recvbuffer[index].size;
    memcpy(data, connection->recvbuffer[index].data, size);
    ++connection->successful_read;
    connection->recvbuffer[index].size = 0;
    return size;

}

/*  return 0 if data could not be put in packet queue.
 *  return 1 if data was put into the queue.
 */
int write_packet(Lossless_UDP *ludp, int connection_id, uint8_t *data, uint32_t length)
{
    if ((unsigned int)connection_id >= ludp->connections.len)
        return 0;

    if (length > MAX_DATA_SIZE || length == 0 || sendqueue(ludp, connection_id) >= BUFFER_PACKET_NUM)
        return 0;

    Connection *connection = &tox_array_get(&ludp->connections, connection_id, Connection);

    if (connection->status == 0)
        return 0;

    uint32_t index = connection->sendbuff_packetnum % MAX_QUEUE_NUM;
    memcpy(connection->sendbuffer[index].data, data, length);
    connection->sendbuffer[index].size = length;
    connection->sendbuff_packetnum++;
    return 1;
}

/* Put the packet numbers the we are missing in requested and return the number. */
uint32_t missing_packets(Lossless_UDP *ludp, int connection_id, uint32_t *requested)
{
    /* Don't request packets if the buffer is full. */
    if (recvqueue(ludp, connection_id) >= (BUFFER_PACKET_NUM - 1))
        return 0;

    uint32_t number = 0;
    uint32_t i;
    uint32_t temp;

    Connection *connection = &tox_array_get(&ludp->connections, connection_id, Connection);

    for (i = connection->recv_packetnum;
            i != connection->osent_packetnum;
            i++) {
        if (connection->recvbuffer[i % MAX_QUEUE_NUM].size == 0) {
            temp = htonl(i);
            memcpy(requested + number, &temp, 4);
            ++number;
        }
    }

    if (number == 0)
        connection->recv_packetnum = connection->osent_packetnum;

    return number;
}

/*
 * BEGIN Packet sending functions.
 * One per packet type.
 * See http://wiki.tox.im/index.php/Lossless_UDP for more information.
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

static int send_SYNC(Lossless_UDP *ludp, int connection_id)
{
    Connection *connection = &tox_array_get(&ludp->connections, connection_id, Connection);
    uint8_t packet[(BUFFER_PACKET_NUM * 4 + 4 + 4 + 2)];
    uint16_t index = 0;

    IP_Port ip_port         = connection->ip_port;
    uint8_t counter         = connection->send_counter;
    uint32_t recv_packetnum = htonl(connection->recv_packetnum);
    uint32_t sent_packetnum = htonl(connection->sent_packetnum);

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

static int send_data_packet(Lossless_UDP *ludp, int connection_id, uint32_t packet_num)
{
    Connection *connection = &tox_array_get(&ludp->connections, connection_id, Connection);

    uint32_t index = packet_num % MAX_QUEUE_NUM;
    uint32_t temp;
    uint8_t packet[1 + 4 + MAX_DATA_SIZE];
    packet[0] = NET_PACKET_DATA;
    temp = htonl(packet_num);
    memcpy(packet + 1, &temp, 4);
    memcpy(packet + 5, connection->sendbuffer[index].data, connection->sendbuffer[index].size);
    return sendpacket(ludp->net->sock, connection->ip_port, packet, 1 + 4 + connection->sendbuffer[index].size);
}

/* Sends 1 data packet. */
static int send_DATA(Lossless_UDP *ludp, int connection_id)
{
    Connection *connection = &tox_array_get(&ludp->connections, connection_id, Connection);
    int ret;
    uint32_t buffer[BUFFER_PACKET_NUM];

    if (connection->num_req_paquets > 0) {
        ret = send_data_packet(ludp, connection_id, connection->req_packets[0]);
        connection->num_req_paquets--;
        memcpy(buffer, connection->req_packets + 1, connection->num_req_paquets * 4);
        memcpy(connection->req_packets, buffer, connection->num_req_paquets * 4);
        return ret;
    }

    if (connection->sendbuff_packetnum != connection->sent_packetnum) {
        ret = send_data_packet(ludp, connection_id, connection->sent_packetnum);
        connection->sent_packetnum++;
        return ret;
    }

    return 0;
}

/*
 * END of packet sending functions.
 *
 *
 * BEGIN Packet handling functions.
 * One to handle each type of packets we receive.
 */


/*  return 0 if handled correctly.
 *  return 1 if packet is bad.
 */
static int handle_handshake(void *object, IP_Port source, uint8_t *packet, uint32_t length)
{
    Lossless_UDP *ludp = object;

    if (length != (1 + 4 + 4))
        return 1;

    uint32_t temp;
    uint32_t handshake_id1, handshake_id2;
    int connection_id = getconnection_id(ludp, source);

    memcpy(&temp, packet + 1, 4);
    handshake_id1 = ntohl(temp);
    memcpy(&temp, packet + 5, 4);
    handshake_id2 = ntohl(temp);


    if (handshake_id2 == 0 && is_connected(ludp, connection_id) < 3) {
        send_handshake(ludp, source, handshake_id(ludp, source), handshake_id1);
        return 0;
    }

    if (is_connected(ludp, connection_id) != 1)
        return 1;

    Connection *connection = &tox_array_get(&ludp->connections, connection_id, Connection);

    /* if handshake_id2 is what we sent previously as handshake_id1 */
    if (handshake_id2 == connection->handshake_id1) {
        connection->status = 2;
        /* NOTE: is this necessary?
        connection->handshake_id2 = handshake_id1; */
        connection->orecv_packetnum = handshake_id2;
        connection->osent_packetnum = handshake_id1;
        connection->recv_packetnum  = handshake_id1;
        connection->successful_read = handshake_id1;
    }

    return 0;
}

/*  return 1 if sync packet is valid.
 *  return 0 if not.
 */
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
        int connection_id = new_inconnection(ludp, source);

        if (connection_id != -1) {
            Connection *connection = &tox_array_get(&ludp->connections, connection_id, Connection);
            connection->orecv_packetnum    = recv_packetnum;
            connection->sent_packetnum     = recv_packetnum;
            connection->sendbuff_packetnum = recv_packetnum;
            connection->successful_sent    = recv_packetnum;
            connection->osent_packetnum    = sent_packetnum;
            connection->recv_packetnum     = sent_packetnum;
            connection->successful_read    = sent_packetnum;

            return connection_id;
        }
    }

    return -1;
}

/* case 2 in handle_SYNC: */
static int handle_SYNC2(Lossless_UDP *ludp, int connection_id, uint8_t counter, uint32_t recv_packetnum,
                        uint32_t sent_packetnum)
{
    Connection *connection = &tox_array_get(&ludp->connections, connection_id, Connection);

    if (recv_packetnum == connection->orecv_packetnum) {
        /* && sent_packetnum == connection->osent_packetnum) */
        connection->status = 3;
        connection->recv_counter = counter;
        ++connection->send_counter;
        send_SYNC(ludp, connection_id);
        return 0;
    }

    return 1;
}
/* case 3 in handle_SYNC: */
static int handle_SYNC3(Lossless_UDP *ludp, int connection_id, uint8_t counter, uint32_t recv_packetnum,
                        uint32_t sent_packetnum,
                        uint32_t *req_packets,
                        uint16_t number)
{
    Connection *connection = &tox_array_get(&ludp->connections, connection_id, Connection);

    uint8_t comp_counter = (counter - connection->recv_counter);
    uint32_t i, temp;
    /* uint32_t comp_1 = (recv_packetnum - connection->successful_sent);
       uint32_t comp_2 = (sent_packetnum - connection->successful_read); */
    uint32_t comp_1 = (recv_packetnum - connection->orecv_packetnum);
    uint32_t comp_2 = (sent_packetnum - connection->osent_packetnum);

    /* Packet valid. */
    if (comp_1 <= BUFFER_PACKET_NUM &&
            comp_2 <= BUFFER_PACKET_NUM &&
            comp_counter < 10 && comp_counter != 0) {
        connection->orecv_packetnum = recv_packetnum;
        connection->osent_packetnum = sent_packetnum;
        connection->successful_sent = recv_packetnum;
        connection->last_recvSYNC   = current_time();
        connection->recv_counter    = counter;

        ++connection->send_counter;

        for (i = 0; i < number; ++i) {
            temp = ntohl(req_packets[i]);
            memcpy(connection->req_packets + i, &temp, 4 * number);
        }

        connection->num_req_paquets = number;
        return 0;
    }

    return 1;
}

static int handle_SYNC(void *object, IP_Port source, uint8_t *packet, uint32_t length)
{
    Lossless_UDP *ludp = object;

    if (!SYNC_valid(length))
        return 1;

    uint8_t counter;
    uint32_t temp;
    uint32_t recv_packetnum, sent_packetnum;
    uint32_t req_packets[BUFFER_PACKET_NUM];
    uint16_t number = (length - 4 - 4 - 2) / 4;

    memcpy(&counter, packet + 1, 1);
    memcpy(&temp, packet + 2, 4);
    recv_packetnum = ntohl(temp);
    memcpy(&temp, packet + 6, 4);
    sent_packetnum = ntohl(temp);

    if (number != 0)
        memcpy(req_packets, packet + 10, 4 * number);

    int connection_id = getconnection_id(ludp, source);

    if (connection_id == -1)
        return handle_SYNC1(ludp, source, recv_packetnum, sent_packetnum);

    Connection *connection = &tox_array_get(&ludp->connections, connection_id, Connection);

    if (connection->status == 2)
        return handle_SYNC2(ludp, connection_id, counter,
                            recv_packetnum, sent_packetnum);

    if (connection->status == 3)
        return handle_SYNC3(ludp, connection_id, counter, recv_packetnum,
                            sent_packetnum, req_packets, number);

    return 0;
}

/*
 * Add a packet to the received buffer and set the recv_packetnum of the
 * connection to its proper value.
 *
 *  return 1 if data was too big.
 *  return 0 if not.
 */
static int add_recv(Lossless_UDP *ludp, int connection_id, uint32_t data_num, uint8_t *data, uint16_t size)
{
    if (size > MAX_DATA_SIZE)
        return 1;

    Connection *connection = &tox_array_get(&ludp->connections, connection_id, Connection);
    uint32_t i;
    uint32_t maxnum = connection->successful_read + BUFFER_PACKET_NUM;
    uint32_t sent_packet = data_num - connection->osent_packetnum;

    for (i = connection->recv_packetnum; i != maxnum; ++i) {
        if (i == data_num) {
            memcpy(connection->recvbuffer[i % MAX_QUEUE_NUM].data, data, size);

            connection->recvbuffer[i % MAX_QUEUE_NUM].size = size;
            connection->last_recvdata = current_time();

            if (sent_packet < BUFFER_PACKET_NUM)
                connection->osent_packetnum = data_num;

            break;
        }
    }

    for (i = connection->recv_packetnum; i != maxnum; ++i) {
        if (connection->recvbuffer[i % MAX_QUEUE_NUM].size != 0)
            connection->recv_packetnum = i;
        else
            break;
    }

    return 0;
}

static int handle_data(void *object, IP_Port source, uint8_t *packet, uint32_t length)
{
    Lossless_UDP *ludp = object;
    int connection_id = getconnection_id(ludp, source);

    /* Drop the data packet if connection is not connected. */
    if (connection_id == -1)
        return 1;

    if (tox_array_get(&ludp->connections, connection_id, Connection).status != 3)
        return 1;

    if (length > 1 + 4 + MAX_DATA_SIZE || length < 1 + 4 + 1)
        return 1;

    uint32_t temp;
    uint32_t number;
    uint16_t size = length - 1 - 4;

    memcpy(&temp, packet + 1, 4);
    number = ntohl(temp);

    return add_recv(ludp, connection_id, number, packet + 5, size);
}

/*
 * END of packet handling functions.
 */

Lossless_UDP *new_lossless_udp(Networking_Core *net)
{
    if (net == NULL)
        return NULL;

    Lossless_UDP *temp = calloc(1, sizeof(Lossless_UDP));

    if (temp == NULL)
        return NULL;

    tox_array_init(&temp->connections, sizeof(Connection));

    temp->net = net;
    networking_registerhandler(net, NET_PACKET_HANDSHAKE, &handle_handshake, temp);
    networking_registerhandler(net, NET_PACKET_SYNC, &handle_SYNC, temp);
    networking_registerhandler(net, NET_PACKET_DATA, &handle_data, temp);
    return temp;
}

/*
 * Send handshake requests.
 * Handshake packets are sent at the same rate as SYNC packets.
 */
static void do_new(Lossless_UDP *ludp)
{
    uint64_t temp_time = current_time();

    tox_array_for_each(&ludp->connections, Connection, tmp) {
        if (tmp->status == 1 && (tmp->last_sent + (1000000UL / tmp->SYNC_rate)) <= temp_time) {
            send_handshake(ludp, tmp->ip_port, tmp->handshake_id1, 0);
            tmp->last_sent = temp_time;
        }

        /* kill all timed out connections */
        if (tmp->status > 0 && (tmp->last_recvSYNC + tmp->timeout * 1000000UL) < temp_time && tmp->status != 4) {
            tmp->status = 4;
            /* kill_connection(i); */
        }

        if (tmp->status > 0 && tmp->killat < temp_time)
            kill_connection(ludp, tmp_i);
    }
}

static void do_SYNC(Lossless_UDP *ludp)
{
    uint64_t temp_time = current_time();

    tox_array_for_each(&ludp->connections, Connection, tmp) {
        if (tmp->status == 2 || tmp->status == 3)
            if ((tmp->last_SYNC + (1000000UL / tmp->SYNC_rate)) <= temp_time) {
                send_SYNC(ludp, tmp_i);
                tmp->last_SYNC = temp_time;
            }
    }
}

static void do_data(Lossless_UDP *ludp)
{
    uint64_t j;
    uint64_t temp_time = current_time();

    tox_array_for_each(&ludp->connections, Connection, tmp) {
        if (tmp->status == 3 && sendqueue(ludp, tmp_i) != 0 &&
                (tmp->last_sent + (1000000UL / tmp->data_rate)) <= temp_time) {
            for (j = tmp->last_sent; j < temp_time; j +=  (1000000UL / tmp->data_rate))
                send_DATA(ludp, tmp_i);

            tmp->last_sent = temp_time;

        }
    }
}

#define MAX_SYNC_RATE 10

/*
 * Automatically adjusts send rates of packets for optimal transmission.
 *
 * TODO: Flow control.
 */
static void adjust_rates(Lossless_UDP *ludp)
{
    uint64_t temp_time = current_time();

    tox_array_for_each(&ludp->connections, Connection, tmp) {
        if (tmp->status == 1 || tmp->status == 2)
            tmp->SYNC_rate = MAX_SYNC_RATE;

        if (tmp->status == 3) {
            if (sendqueue(ludp, tmp_i) != 0) {
                tmp->data_rate = (BUFFER_PACKET_NUM - tmp->num_req_paquets) * MAX_SYNC_RATE;
                tmp->SYNC_rate = MAX_SYNC_RATE;
            } else if (tmp->last_recvdata + 1000000UL > temp_time)
                tmp->SYNC_rate = MAX_SYNC_RATE;
            else
                tmp->SYNC_rate = SYNC_RATE;
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
    tox_array_delete(&ludp->connections);
    free(ludp);
}
