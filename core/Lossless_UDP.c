/* Lossless_UDP.c
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
//TODO: clean this file a bit.
//There are a couple of useless variables to get rid of.
#include "Lossless_UDP.h"



//maximum data packets in sent and receive queues.
#define MAX_QUEUE_NUM 16

//maximum length of the data in the data packets
//#define MAX_DATA_SIZE 1024 //defined in Lossless_UDP.h

//maximum number of data packets in the buffer
#define BUFFER_PACKET_NUM (16-1)

//Lossless UDP connection timeout.
#define CONNEXION_TIMEOUT 5

//initial amount of sync/hanshake packets to send per second.
#define SYNC_RATE 10

//initial send rate of data.
#define DATA_SYNC_RATE 30

typedef struct
{
    uint8_t data[MAX_DATA_SIZE];
    uint16_t size;
}Data;

typedef struct
{
    IP_Port ip_port;
    uint8_t status;//0 if connection is dead, 1 if attempting handshake, 
                //2 if handshake is done (we start sending SYNC packets)
                //3 if we are sending SYNC packets and can send data
                //4 if the connection has timed out.
    
    uint8_t inbound; //1 or 2 if connection was initiated by someone else, 0 if not. 
                  //2 if incoming_connection() has not returned it yet, 1 if it has.
                  
    uint16_t SYNC_rate;//current SYNC packet send rate packets per second.
    uint16_t data_rate;//current data packet send rate packets per second.
    uint64_t last_SYNC; //time at which our last SYNC packet was sent.
    uint64_t last_sent; //time at which our last data or handshake packet was sent.
    uint64_t last_recv; //time at which we last received something from the other
    uint64_t killat; //time at which to kill the connection
    Data sendbuffer[MAX_QUEUE_NUM];//packet send buffer.
    Data recvbuffer[MAX_QUEUE_NUM];//packet receive buffer.
    uint32_t handshake_id1;
    uint32_t handshake_id2;
    uint32_t recv_packetnum; //number of data packets received (also used as handshake_id1)
    uint32_t orecv_packetnum; //number of packets received by the other peer
    uint32_t sent_packetnum; //number of data packets sent
    uint32_t osent_packetnum; //number of packets sent by the other peer.
    uint32_t sendbuff_packetnum; //number of latest packet written onto the sendbuffer
    uint32_t successful_sent;//we know all packets before that number were successfully sent
    uint32_t successful_read;//packet number of last packet read with the read_packet function
    uint32_t req_packets[BUFFER_PACKET_NUM]; //list of currently requested packet numbers(by the other person)
    uint16_t num_req_paquets; //total number of currently requested packets(by the other person)
    uint8_t recv_counter;
    uint8_t send_counter;
}Connection;


#define MAX_CONNECTIONS 256

Connection connections[MAX_CONNECTIONS];

//Functions

//get connection id from IP_Port
//return -1 if there are no connections like we are looking for
//return id if it found it
int getconnection_id(IP_Port ip_port)
{
    uint32_t i;
    for(i = 0; i < MAX_CONNECTIONS; i++ )
    {
            if(connections[i].ip_port.ip.i == ip_port.ip.i && 
            connections[i].ip_port.port == ip_port.port && connections[i].status > 0)
            {
                    return i;
            }
    }
    return -1;
}

//table of random numbers used below.
static uint32_t randtable[6][256];


//generate a handshake_id which depends on the ip_port.
//this function will always give one unique handshake_id per ip_port.
//TODO: make this better
uint32_t handshake_id(IP_Port source)
{
    uint32_t id = 0, i;
    for(i = 0; i < 6; i++)
    {
        if(randtable[i][((uint8_t *)&source)[i]] == 0)
        {
            randtable[i][((uint8_t *)&source)[i]] = random_int();
        }
        id ^= randtable[i][((uint8_t *)&source)[i]];
    }
    if(id == 0)//id can't be zero
    {
        id = 1;
    }
    return id;
}
//change the hnshake id associated with that ip_port
//TODO: make this better
void change_handshake(IP_Port source)
{
    uint8_t rand = random_int() % 4;
    randtable[rand][((uint8_t *)&source)[rand]] = random_int();
}


//initialize a new connection to ip_port
//returns an integer corresponding to the connection id.
//return -1 if it could not initialize the connection.
//if there already was an existing connection to that ip_port return its number.
int new_connection(IP_Port ip_port)
{
    int connect = getconnection_id(ip_port);
    if(connect != -1)
    {
        return connect;
    }
    uint32_t i;
    for(i = 0; i < MAX_CONNECTIONS; i++)
    {
        if(connections[i].status == 0)
        {
            memset(&connections[i], 0, sizeof(Connection));
            connections[i].ip_port = ip_port;
            connections[i].status = 1;
            connections[i].inbound = 0;
            connections[i].handshake_id1 = handshake_id(ip_port);
            connections[i].sent_packetnum = connections[i].handshake_id1;
            connections[i].sendbuff_packetnum = connections[i].handshake_id1;
            connections[i].successful_sent = connections[i].handshake_id1;
            connections[i].SYNC_rate = SYNC_RATE;
            connections[i].data_rate = DATA_SYNC_RATE;
            connections[i].last_recv = current_time();
            connections[i].killat = ~0;
            connections[i].send_counter = 0;
            return i;
        }
    }
    return -1;
}

//initialize a new inbound connection from ip_port
//returns an integer corresponding to the connection id.
//return -1 if it could not initialize the connection.
int new_inconnection(IP_Port ip_port)
{
    if(getconnection_id(ip_port) != -1)
    {
        return -1;
    }
    uint32_t i;
    for(i = 0; i < MAX_CONNECTIONS; i++)
    {
        if(connections[i].status == 0)
        {
            memset(&connections[i], 0, sizeof(Connection));
            connections[i].ip_port = ip_port;
            connections[i].status = 2;
            connections[i].inbound = 2;
            connections[i].SYNC_rate = SYNC_RATE;
            connections[i].data_rate = DATA_SYNC_RATE;
            connections[i].last_recv = current_time();
            //if this connection isn't handled within 5 seconds, kill it
            connections[i].killat = current_time() + 1000000UL*CONNEXION_TIMEOUT;
            connections[i].send_counter = 127;
            return i;
        }
    }
    return -1;
}

//returns an integer corresponding to the next connection in our incoming connection list
//return -1 if there are no new incoming connections in the list.
int incoming_connection()
{
    uint32_t i;
    for(i = 0; i < MAX_CONNECTIONS; i++)
    {
        if(connections[i].inbound == 2)
        {
            connections[i].inbound = 1;
            return i;
        }
    }
    return -1;
}

//return -1 if it could not kill the connection.
//return 0 if killed successfully
int kill_connection(int connection_id)
{
    if(connection_id >= 0 && connection_id < MAX_CONNECTIONS)
    {
        if(connections[connection_id].status > 0)
        {
                connections[connection_id].status = 0;
                change_handshake(connections[connection_id].ip_port);
                return 0;
        }
    }
    return -1;
}

//kill connection in seconds seconds.
//return -1 if it can not kill the connection.
//return 0 if it will kill it
int kill_connection_in(int connection_id, uint32_t seconds)
{
    if(connection_id >= 0 && connection_id < MAX_CONNECTIONS)
    {
        if(connections[connection_id].status > 0)
        {
                connections[connection_id].killat = current_time() + 1000000UL*seconds;
                return 0;
        }
    }
    return -1;
}

//check if connection is connected
//return 0 no.
//return 1 if attempting handshake
//return 2 if handshake is done
//return 3 if fully connected
//return 4 if timed out and waiting to be killed
int is_connected(int connection_id)
{
    if(connection_id >= 0 && connection_id < MAX_CONNECTIONS)
    {
        return connections[connection_id].status;
    }
    return 0;
}

//returns the ip_port of the corresponding connection.
IP_Port connection_ip(int connection_id)
{
    if(connection_id >= 0 && connection_id < MAX_CONNECTIONS)
    {
        return connections[connection_id].ip_port;
    }
    IP_Port zero = {{{0}}, 0};
    return zero;
}

//returns the number of packets in the queue waiting to be successfully sent.
uint32_t sendqueue(int connection_id)
{
    return connections[connection_id].sendbuff_packetnum - connections[connection_id].successful_sent;
}

//returns the number of packets in the queue waiting to be successfully read with read_packet(...)
uint32_t recvqueue(int connection_id)
{
    return connections[connection_id].recv_packetnum - connections[connection_id].successful_read;
}

//returns the id of the next packet in the queue
//return -1 if no packet in queue
char id_packet(int connection_id)
{
    if(recvqueue(connection_id) != 0 && connections[connection_id].status != 0)
    {
        return connections[connection_id].recvbuffer[connections[connection_id].successful_read % MAX_QUEUE_NUM].data[0];
    }
    return -1;
}
//return 0 if there is no received data in the buffer.
//return length of received packet if successful
int read_packet(int connection_id, uint8_t * data)
{
    if(recvqueue(connection_id) != 0)
    {
        uint16_t index = connections[connection_id].successful_read % MAX_QUEUE_NUM;
        uint16_t size = connections[connection_id].recvbuffer[index].size;
        memcpy(data, connections[connection_id].recvbuffer[index].data, size);
        connections[connection_id].successful_read++;
        connections[connection_id].recvbuffer[index].size = 0;
        return size;
    }
    return 0;
}

//return 0 if data could not be put in packet queue
//return 1 if data was put into the queue
int write_packet(int connection_id, uint8_t * data, uint32_t length)
{
    if(length > MAX_DATA_SIZE)
    {
        return 0;
    }
    if(length == 0)
    {
        return 0;
    }
    if(sendqueue(connection_id) <  BUFFER_PACKET_NUM)
    {
        uint32_t index = connections[connection_id].sendbuff_packetnum % MAX_QUEUE_NUM;
        memcpy(connections[connection_id].sendbuffer[index].data, data, length);
        connections[connection_id].sendbuffer[index].size = length;
        connections[connection_id].sendbuff_packetnum++;
        return 1;
    }
    return 0;
}




//put the packet numbers the we are missing in requested and return the number
uint32_t missing_packets(int connection_id, uint32_t * requested)
{
    uint32_t number = 0;
    uint32_t i;
    uint32_t temp;
    if(recvqueue(connection_id) >= (BUFFER_PACKET_NUM - 1))//don't request packets if the buffer is full.
    {
        return 0;
    }
    for(i = connections[connection_id].recv_packetnum; i != connections[connection_id].osent_packetnum; i++ )
    {
        if(connections[connection_id].recvbuffer[i % MAX_QUEUE_NUM].size == 0)
        {
            temp = htonl(i);
            memcpy(requested + number, &temp, 4);
            number++;
        }
    }
    if(number == 0)
    {
        connections[connection_id].recv_packetnum = connections[connection_id].osent_packetnum;
    }
    return number;
    
}

//Packet sending functions
//One per packet type.
//see docs/Lossless_UDP.txt for more information.


int send_handshake(IP_Port ip_port, uint32_t handshake_id1, uint32_t handshake_id2)
{
    uint8_t packet[1 + 4 + 4];
    uint32_t temp;
    
    packet[0] = 16;
    temp = htonl(handshake_id1);
    memcpy(packet + 1, &temp, 4);
    temp = htonl(handshake_id2);
    memcpy(packet + 5, &temp, 4);
    return sendpacket(ip_port, packet, sizeof(packet));
    
}


int send_SYNC(uint32_t connection_id)
{
    
    uint8_t packet[(BUFFER_PACKET_NUM*4 + 4 + 4 + 2)];
    uint16_t index = 0;
    
    IP_Port ip_port = connections[connection_id].ip_port;
    uint8_t counter = connections[connection_id].send_counter;
    uint32_t recv_packetnum = htonl(connections[connection_id].recv_packetnum);
    uint32_t sent_packetnum = htonl(connections[connection_id].sent_packetnum);
    uint32_t requested[BUFFER_PACKET_NUM];
    uint32_t number = missing_packets(connection_id, requested);
    
    packet[0] = 17;
    index += 1;
    memcpy(packet + index, &counter, 1);
    index += 1;
    memcpy(packet + index, &recv_packetnum, 4);
    index += 4;
    memcpy(packet + index, &sent_packetnum, 4);
    index += 4;
    memcpy(packet + index, requested, 4 * number);

    return sendpacket(ip_port, packet, (number*4 + 4 + 4 + 2));
   
}

int send_data_packet(uint32_t connection_id, uint32_t packet_num)
{
    uint32_t index = packet_num % MAX_QUEUE_NUM;
    uint32_t temp;
    uint8_t packet[1 + 4 + MAX_DATA_SIZE];
    packet[0] = 18;
    temp = htonl(packet_num);
    memcpy(packet + 1, &temp, 4);
    memcpy(packet + 5, connections[connection_id].sendbuffer[index].data, 
                       connections[connection_id].sendbuffer[index].size);
    return sendpacket(connections[connection_id].ip_port, packet,
               1 + 4 + connections[connection_id].sendbuffer[index].size);
}

//sends 1 data packet
int send_DATA(uint32_t connection_id)
{
    int ret;
    uint32_t buffer[BUFFER_PACKET_NUM];
    if(connections[connection_id].num_req_paquets > 0)
    {  
        ret = send_data_packet(connection_id, connections[connection_id].req_packets[0]);
        connections[connection_id].num_req_paquets--;
        memcpy(buffer, connections[connection_id].req_packets + 1, connections[connection_id].num_req_paquets * 4);
        memcpy(connections[connection_id].req_packets, buffer, connections[connection_id].num_req_paquets * 4);
        return ret;
    }
    if(connections[connection_id].sendbuff_packetnum != connections[connection_id].sent_packetnum)
    {
        ret = send_data_packet(connection_id, connections[connection_id].sent_packetnum);
        connections[connection_id].sent_packetnum++;
        return ret;
    }
    return 0;
}

//END of packet sending functions



//Packet handling functions
//One to handle each type of packets we receive
//return 0 if handled correctly, 1 if packet is bad.
int handle_handshake(uint8_t * packet, uint32_t length, IP_Port source)
{    
    if(length != (1 + 4 + 4))
    {
            return 1;
    }
    uint32_t temp;
    uint32_t handshake_id1, handshake_id2;
    int connection = getconnection_id(source);
    memcpy(&temp, packet + 1, 4);
    handshake_id1 = ntohl(temp);
    memcpy(&temp, packet + 5, 4);
    handshake_id2 = ntohl(temp);
    
    if(handshake_id2 == 0)
    {
        send_handshake(source, handshake_id(source), handshake_id1);
        return 0;
    }
    if(is_connected(connection) != 1)
    {
        return 1;
    }
    if(handshake_id2 == connections[connection].handshake_id1)//if handshake_id2 is what we sent previously as handshake_id1
    {
        connections[connection].status = 2;
        //NOTE:is this necessary?
        //connections[connection].handshake_id2 = handshake_id1;
        connections[connection].orecv_packetnum = handshake_id2;
        connections[connection].osent_packetnum = handshake_id1;
        connections[connection].recv_packetnum = handshake_id1;
        connections[connection].successful_read = handshake_id1;
    }
    return 0;

}

//returns 1 if sync packet is valid
//0 if not.
int SYNC_valid(uint32_t length)
{
    if(length < 4 + 4 + 2)
    {
        return 0;
    }
    if(length > (BUFFER_PACKET_NUM*4 + 4 + 4 + 2) || 
    ((length - 4 - 4 - 2) % 4) != 0)
    {
        return 0;
    }
    return 1;
}

//case 1: 
int handle_SYNC1(IP_Port source, uint32_t recv_packetnum, uint32_t sent_packetnum)
{
    if(handshake_id(source) == recv_packetnum)
    {
        int x = new_inconnection(source);
        if(x != -1)
        {
            connections[x].orecv_packetnum = recv_packetnum;
            connections[x].sent_packetnum = recv_packetnum;
            connections[x].sendbuff_packetnum = recv_packetnum;
            connections[x].successful_sent = recv_packetnum;
            connections[x].osent_packetnum = sent_packetnum;
            connections[x].recv_packetnum = sent_packetnum;
            connections[x].successful_read = sent_packetnum;

            return x;
        }
    }
    return -1;
}

//case 2:
int handle_SYNC2(int connection_id, uint8_t counter, uint32_t recv_packetnum, uint32_t sent_packetnum)
{
    if(recv_packetnum == connections[connection_id].orecv_packetnum)
       //&& sent_packetnum == connections[connection_id].osent_packetnum)
    {
        connections[connection_id].status =  3;
        connections[connection_id].recv_counter = counter;
        connections[connection_id].send_counter++;
        return 0;
    }
    return 1;
}
//case 3:
int handle_SYNC3(int connection_id, uint8_t counter, uint32_t recv_packetnum, uint32_t sent_packetnum, uint32_t * req_packets,
                 uint16_t number)
{
    uint8_t comp_counter = (counter - connections[connection_id].recv_counter );
    uint32_t i, temp;
    //uint32_t comp_1 = (recv_packetnum - connections[connection_id].successful_sent);
    //uint32_t comp_2 = (sent_packetnum - connections[connection_id].successful_read);
    uint32_t comp_1 = (recv_packetnum - connections[connection_id].orecv_packetnum);
    uint32_t comp_2 = (sent_packetnum - connections[connection_id].osent_packetnum);
    if(comp_1 <= BUFFER_PACKET_NUM && comp_2 <= BUFFER_PACKET_NUM && comp_counter < 10 && comp_counter != 0) //packet valid
    {
        connections[connection_id].orecv_packetnum = recv_packetnum;
        connections[connection_id].osent_packetnum = sent_packetnum;
        connections[connection_id].successful_sent = recv_packetnum;
        connections[connection_id].last_recv = current_time();
        connections[connection_id].recv_counter = counter;
        connections[connection_id].send_counter++;
        for(i = 0; i < number; i++)
        {
            temp = ntohl(req_packets[i]);
            memcpy(connections[connection_id].req_packets + i, &temp, 4 * number);
        }
        connections[connection_id].num_req_paquets = number;
        return 0;
    }
    return 1;
}

int handle_SYNC(uint8_t * packet, uint32_t length, IP_Port source)
{

    if(!SYNC_valid(length))
    {
        return 1;   
    }
    int connection = getconnection_id(source);
    uint8_t counter;
    uint32_t temp;
    uint32_t recv_packetnum, sent_packetnum;
    uint32_t req_packets[BUFFER_PACKET_NUM];
    uint16_t number = (length - 4 - 4 - 2)/ 4;
    
    memcpy(&counter, packet + 1, 1);
    memcpy(&temp, packet + 2, 4);
    recv_packetnum = ntohl(temp);
    memcpy(&temp,packet + 6,  4);
    sent_packetnum = ntohl(temp);
    if(number != 0)
    {
        memcpy(req_packets, packet + 10,  4 * number);
    }
    if(connection == -1)
    {
        return handle_SYNC1(source, recv_packetnum, sent_packetnum);
    }
    if(connections[connection].status ==  2)
    {
        return handle_SYNC2(connection, counter, recv_packetnum, sent_packetnum);
    }
    if(connections[connection].status ==  3)
    {
        return handle_SYNC3(connection, counter, recv_packetnum, sent_packetnum, req_packets, number);
    }    
    return 0;
}

//add a packet to the received buffer and set the recv_packetnum of the connection to its proper value.
//return 1 if data was too big, 0 if not.
int add_recv(int connection_id, uint32_t data_num, uint8_t * data, uint16_t size)
{
    if(size > MAX_DATA_SIZE)
    {
        return 1;
    }

    uint32_t i;
    uint32_t maxnum = connections[connection_id].successful_read + BUFFER_PACKET_NUM;
    uint32_t sent_packet = data_num - connections[connection_id].osent_packetnum;
    for(i =  connections[connection_id].recv_packetnum; i != maxnum; i++)
    {    
        if(i == data_num)
        {
            memcpy(connections[connection_id].recvbuffer[i % MAX_QUEUE_NUM].data, data, size);
            connections[connection_id].recvbuffer[i % MAX_QUEUE_NUM].size = size;
            if(sent_packet < BUFFER_PACKET_NUM)
            {
                connections[connection_id].osent_packetnum = data_num;
            }
            break;
        }
    }
    for(i = connections[connection_id].recv_packetnum; i != maxnum; i++)
    {
        if(connections[connection_id].recvbuffer[i % MAX_QUEUE_NUM].size != 0)
        {
             connections[connection_id].recv_packetnum = i;
        }
        else
        {
            break;
        }
    }

    return 0;
}

int handle_data(uint8_t * packet, uint32_t length, IP_Port source)
{
    int connection = getconnection_id(source);
    
    if(connection == -1)
    {
        return 1;
    }
    if(length > 1 + 4 + MAX_DATA_SIZE || length < 1 + 4 + 1)
    {
        return 1;
    }
    uint32_t temp;
    uint32_t number;
    uint16_t size = length - 1 - 4;
    
    memcpy(&temp, packet + 1, 4);
    number = ntohl(temp);
    return add_recv(connection, number, packet + 5, size);
    
}

//END of packet handling functions


int LosslessUDP_handlepacket(uint8_t * packet, uint32_t length, IP_Port source)
{

    switch (packet[0]) {
    case 16:
        return handle_handshake(packet, length, source);   
        
    case 17:
        return handle_SYNC(packet, length, source); 
        
    case 18:
        return handle_data(packet, length, source); 
        
    default: 
        return 1;
        
    }
    
    return 0;
        
}

//Send handshake requests
//handshake packets are sent at the same rate as SYNC packets
void doNew()
{
    uint32_t i;
    uint64_t temp_time = current_time();
    for(i = 0; i < MAX_CONNECTIONS; i++)
    {
        if(connections[i].status == 1)
        {
            if((connections[i].last_sent + (1000000UL/connections[i].SYNC_rate)) <= temp_time)
            {
               send_handshake(connections[i].ip_port, connections[i].handshake_id1, 0);
               connections[i].last_sent = temp_time;
            }

        }
        //kill all timed out connections
        if( connections[i].status > 0 && (connections[i].last_recv + CONNEXION_TIMEOUT * 1000000UL) < temp_time && 
            connections[i].status != 4)
        {
            //kill_connection(i);
            connections[i].status = 4;
        }
        if(connections[i].status > 0 && connections[i].killat < temp_time)
        {
            kill_connection(i);
        }
    }
}

void doSYNC()
{
    uint32_t i;
    uint64_t temp_time = current_time();
    for(i = 0; i < MAX_CONNECTIONS; i++)
    {
        if(connections[i].status == 2 || connections[i].status == 3)
        {
            if((connections[i].last_SYNC + (1000000UL/connections[i].SYNC_rate)) <= temp_time)
            {
               send_SYNC(i);
               connections[i].last_SYNC = temp_time;
            }
        }
    }
}

void doData()
{
    uint32_t i;
    uint64_t temp_time = current_time();
    for(i = 0; i < MAX_CONNECTIONS; i++)
    {
        if(connections[i].status == 3)
        {
            if((connections[i].last_sent + (1000000UL/connections[i].data_rate)) <= temp_time)
            {
               send_DATA(i);
               connections[i].last_sent = temp_time;
            }
        }
    }    
}

//TODO: flow control.
//automatically adjusts send rates of packets for optimal transmission.
void adjustRates()
{
    //if()
    
}

//Call this function a couple times per second
//It's the main loop.
void doLossless_UDP()
{
    doNew();
    doSYNC();
    doData();
    adjustRates();
    
    
}