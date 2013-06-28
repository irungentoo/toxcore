/* Lossless_UDP.h
* 
* An implementation of the Lossless_UDP protocol as seen in docs/Lossless_UDP.txt
* 
*/
#ifndef LOSSLESS_UDP_H 
#define LOSSLESS_UDP_H  

#include "network.h"




//Functions

//initialize a new connection to ip_port
//returns an integer corresponding to the connection id.
//return -1 if it could not initialize the connection.
int new_connection(IP_Port ip_port);

//returns an integer corresponding to the next connection in our imcoming connection list
//return -1 if there are no new incoming connections in the list.
int incoming_connection();

//return -1 if it could not kill the connection.
//return 0 if killed successfully
int kill_connection(int connection_id);

//return 0 if there is no received data in the buffer.
//return length of recieved packet if successful
int read_packet(int connection_id, char * data);

//return 0 if data could not be put in packet queue
//return 1 if data was put into the queue
int write_packet(int connection_id, char * data, uint32_t length);

//returns the number of packets in the queue waiting to be successfully sent.
int sendqueue(int connection_id);

//returns the number of packets in the queue waiting to be successfully read with read_packet(...)
int recvqueue(int connection_id);

//check if connection is connected
//return 0 no.
//return 1 if yes
//return 2 if the initial attempt isn't over yet.
int is_connected(int connection_id);

//Call this function a couple times per second
//It's the main loop.
void doLossless_UDP();

//if we receive a Lossless_UDP packet we call this function so it can be handled.
//Return 0 if packet is handled correctly.
//return 1 if it didn't handle the packet or if the packet was shit.
int LosslessUDP_handlepacket(char * packet, uint32_t length, IP_Port source);

#endif