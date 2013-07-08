/* Lossless_UDP.h
* 
* An implementation of the Lossless_UDP protocol as seen in docs/Lossless_UDP.txt
* 
 
    Copyright (C) 2013 Tox project All Rights Reserved.

    This file is part of Tox.

    Tox is free software: you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation, either version 3 of the License, or
    (at your option) any later version.

    Tox is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with Tox.  If not, see <http://www.gnu.org/licenses/>.
    
*/

#ifndef LOSSLESS_UDP_H 
#define LOSSLESS_UDP_H  

#include "network.h"


//maximum length of the data in the data packets
#define MAX_DATA_SIZE 1024



//Functions

//initialize a new connection to ip_port
//returns an integer corresponding to the connection id.
//return -1 if it could not initialize the connection.
//if there already was an existing connection to that ip_port return its number.
int new_connection(IP_Port ip_port);

//get connection id from IP_Port
//return -1 if there are no connections like we are looking for
//return id if it found it
int getconnection_id(IP_Port ip_port);

//returns an integer corresponding to the next connection in our imcoming connection list
//return -1 if there are no new incoming connections in the list.
int incoming_connection();


//return -1 if it could not kill the connection.
//return 0 if killed successfully
int kill_connection(int connection_id);

//kill connection in seconds seconds.
//return -1 if it can not kill the connection.
//return 0 if it will kill it
int kill_connection_in(int connection_id, uint32_t seconds);

//returns the ip_port of the corresponding connection.
//return 0 if there is no such connection.
IP_Port connection_ip(int connection_id);

//returns the id of the next packet in the queue
//return -1 if no packet in queue
char id_packet(int connection_id);

//return 0 if there is no received data in the buffer.
//return length of received packet if successful
int read_packet(int connection_id, uint8_t * data);


//return 0 if data could not be put in packet queue
//return 1 if data was put into the queue
int write_packet(int connection_id, uint8_t * data, uint32_t length);



//returns the number of packets in the queue waiting to be successfully sent.
uint32_t sendqueue(int connection_id);


//returns the number of packets in the queue waiting to be successfully read with read_packet(...)
uint32_t recvqueue(int connection_id);


//check if connection is connected
//return 0 no.
//return 1 if attempting handshake
//return 2 if handshake is done
//return 3 if fully connected
//return 4 if timed out and wating to be killed
int is_connected(int connection_id);


//Call this function a couple times per second
//It's the main loop.
void doLossless_UDP();


//if we receive a Lossless_UDP packet we call this function so it can be handled.
//Return 0 if packet is handled correctly.
//return 1 if it didn't handle the packet or if the packet was shit.
int LosslessUDP_handlepacket(uint8_t * packet, uint32_t length, IP_Port source);

#endif
