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

#ifdef __cplusplus
extern "C" {
#endif

/* maximum length of the data in the data packets */
#define MAX_DATA_SIZE 1024

/* 
 * Initialize a new connection to ip_port
 * Returns an integer corresponding to the connection id.
 * Return -1 if it could not initialize the connection.
 * Return number if there already was an existing connection to that ip_port.
 */
int new_connection(IP_Port ip_port);

/* 
 * Get connection id from IP_Port.
 * Return -1 if there are no connections like we are looking for.
 * Return id if it found it .
 */
int getconnection_id(IP_Port ip_port);

/* 
 * Returns an int corresponding to the next connection in our imcoming connection list
 * Return -1 if there are no new incoming connections in the list.
 */
int incoming_connection();

/* 
 * Return -1 if it could not kill the connection.
 * Return 0 if killed successfully
 */
int kill_connection(int connection_id);

/* 
 * Kill connection in seconds seconds.
 * Return -1 if it can not kill the connection.
 * Return 0 if it will kill it
 */
int kill_connection_in(int connection_id, uint32_t seconds);

/* 
 * Returns the ip_port of the corresponding connection.
 * Return 0 if there is no such connection.
 */
IP_Port connection_ip(int connection_id);

/* 
 * Returns the id of the next packet in the queue 
 * Return -1 if no packet in queue 
 */
char id_packet(int connection_id);

/* 
 * Return 0 if there is no received data in the buffer.
 * Return length of received packet if successful 
 */
int read_packet(int connection_id, uint8_t *data);

/* 
 * Return 0 if data could not be put in packet queue
 * Return 1 if data was put into the queue
 */
int write_packet(int connection_id, uint8_t *data, uint32_t length);

/* Returns the number of packets in the queue waiting to be successfully sent. */
uint32_t sendqueue(int connection_id);

/* 
 * returns the number of packets in the queue waiting to be successfully 
 * read with read_packet(...)
 */
uint32_t recvqueue(int connection_id);

/* Check if connection is connected:
 * Return 0 no.
 * Return 1 if attempting handshake.
 * Return 2 if handshake is done.
 * Return 3 if fully connected.
 * Return 4 if timed out and wating to be killed.
 */
int is_connected(int connection_id);

/* Call this function a couple times per second It's the main loop. */
void do_Lossless_UDP();

/* 
 * If we receive a Lossless_UDP packet, call this function so it can be handled.
 * Return 0 if packet is handled correctly.
 * Return 1 if it didn't handle the packet or if the packet was shit.
 */
int Lossless_UDP_handlepacket(uint8_t *packet, uint32_t length, IP_Port source);

#ifdef __cplusplus
}
#endif

#endif
