/* Lossless_UDP.c
* 
* An implementation of the Lossless_UDP protocol as seen in docs/Lossless_UDP.txt
* 
*/
#include "Lossless_UDP.h"


//maximum data packets in sent and recieve queues.
#define MAX_QUEUE_NUM 32

//maximum length of the data in the data packets
#define PDATA_SIZE 1024

//maximum number of data packets that can be sent/recieved at the same time
#define MAX_PACKET_NUM (MAX_QUEUE_NUM/4)

//Lossless UDP connection timeout.
#define CONNEXION_TIMEOUT 10

typedef struct
{
    char data[PDATA_SIZE];
    uint16_t size;
}Data;

typedef struct
{
    IP_Port ip_port;
    char status;//0 if connection is dead, 1 if attempting handshake, 
                //2 if handshake is done (we start sending SYNC packets)
                //3 if we are sending SYNC packets and can send data
    
    char inbound; //1 or 2 if connection was initiated by someone else, 0 if not. 
                  //2 if incoming_connection() has not returned it yet, 1 if it has.
                  
    uint16_t SYNC_rate;//current SYNC packet send rate packets per second.
    uint16_t data_rate;//current data packet send rate packets per second.
    uint64_t last_SYNC; //time at which our last SYNC packet was sent.
    uint64_t last_recv; //time at which we last recieved something from the other
    uint16_t SYNC_packetsize; 
    char SYNC_packet[(MAX_PACKET_NUM*4 + 4 + 4 + 3)]; //the SYNC packet itself
    Data sendbuffer[MAX_PACKET_NUM];//packet send buffer.
    Data recvbuffer[MAX_PACKET_NUM];//packet recieve buffer.
    uint32_t recv_packetnum; //number of data packets recieved (also used as handshake_id1)
    uint32_t sent_packetnum; //number of data packets sent
    uint32_t successful_sent;//we know all packets before that number were successfully sent
    uint32_t successful_read;//packet number of last packet read with the read_packet function
    uint32_t req_packets[MAX_PACKET_NUM]; //list of currently requested packet numbers.
    uint16_t num_req_paquets; //total number of currently requested packets
    uint8_t counter;
}Connection;


#define MAX_CONNECTIONS 256

Connection connections[MAX_CONNECTIONS];


//Functions

//initialize a new connection to ip_port
//returns an integer corresponding to the connection id.
//return -1 if it could not initialize the connection.
int new_connection(IP_Port ip_port)
{
    uint32_t i;
    for(i = 0; i < MAX_CONNECTIONS; i++)
    {
        if(connections[i].status == 0)
        {
            connections[i].status = 1;
            connections[i].inbound = 0;
            connections[i].recv_packetnum = random_int(); //handshake_id1
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
    if(connections[connection_id].status > 0)
    {
            connections[connection_id].status = 0;
            return 0;
    }
    return -1;
}

//return 0 if there is no received data in the buffer.
//return length of received packet if successful
int read_packet(int connection_id, char * data)
{
    //NOTE: like this to handle overflow
    if(connections[connection_id].recv_packetnum - connections[connection_id].successful_read < MAX_QUEUE_NUM &&
       connections[connection_id].recv_packetnum - connections[connection_id].successful_read !=  0)
    {
        uint16_t index  = (connections[connection_id].successful_read % MAX_QUEUE_NUM);
        memcpy(data, connections[connection_id].sendbuffer[index].data, 
        connections[connection_id].sendbuffer[index].size);
        connections[connection_id].successful_read++;
        return connections[connection_id].sendbuffer[index].size;
    }
    return 0;
}

//return 0 if data could not be put in packet queue
//return 1 if data was put into the queue
int write_packet(int connection_id, char * data, uint32_t length)
{
    //NOTE: like this to handle overflow
    if(connections[connection_id].sent_packetnum - connections[connection_id].successful_sent < MAX_QUEUE_NUM)
    {
        uint16_t index  = (connections[connection_id].successful_sent % MAX_QUEUE_NUM);
        memcpy(connections[connection_id].sendbuffer[index].data, data, length);
        connections[connection_id].sendbuffer[index].size = length;
        return 1;
    }
    return 0;
}

//returns the number of packets in the queue waiting to be successfully sent.
int sendqueue(int connection_id)
{
    return connections[connection_id].sent_packetnum - connections[connection_id].successful_sent;
}

//returns the number of packets in the queue waiting to be successfully read with read_packet(...)
int recvqueue(int connection_id)
{
    return connections[connection_id].recv_packetnum - connections[connection_id].successful_read;
}

//check if connection is connected
//return 0 no.
//return 1 if attempting handshake
//return 2 if handshake is done
//return 3 if fully connected
int is_connected(int connection_id)
{
    return connections[connection_id].status;
}

//add a packet number to the list of packet numbers we are requesting
//return 0 if added successfully
//return 1 if it did not because the list was full (should never ever happen)
int request_packet(int connection_id, uint32_t number)
{
    if(connections[connection_id].num_req_paquets >= MAX_PACKET_NUM)
    {
        connections[connection_id].req_packets[connections[connection_id].num_req_paquets] = number;
        connections[connection_id].num_req_paquets++;
        return 0;
    }
    return 1;
    
}

//remove a packet number from the list of packet numbers we are requesting
//return 0 if removed successfully
//return 1 if it did not because it was not in the list.
int unrequest_packet(int connection_id, uint32_t number)
{
    uint32_t i;
    for(i = 0; i < connections[connection_id].num_req_paquets; i++)
    {
        if(connections[connection_id].req_packets[i] == number)
        {
            connections[connection_id].num_req_paquets--;
            connections[connection_id].req_packets[i] = 
            connections[connection_id].req_packets[connections[connection_id].num_req_paquets];
            return 0;
        }
    }
    return 1;
}



//Packet sending functions
//One per packet type.
//see docs/Lossless_UDP.txt for more information.


int send_handshake(IP_Port ip_port, uint32_t handshake_id1, uint32_t handshake_id2)
{
    char packet[1 + 4 + 4];
    packet[0] = 16;
    memcpy(packet + 1, &handshake_id1, 4);
    memcpy(packet + 5, &handshake_id2, 4);
    return sendpacket(ip_port, packet, sizeof(packet));
    
}


int send_SYNC(IP_Port ip_port, char type, uint8_t counter, uint32_t recv_packetnum, 
    uint32_t sent_packetnum, uint32_t * requested, uint32_t number)
{
    if(number > MAX_PACKET_NUM)
    {
        return -1;
    }
    char packet[(MAX_PACKET_NUM*4 + 4 + 4 + 3)];
    uint16_t index = 0;
    
    packet[0] = 17;
    packet[1] = type;
    index += 2;
    memcpy(packet + index, &counter, 1);
    index += 1;
    memcpy(packet + index, &recv_packetnum, 4);
    index += 4;
    memcpy(packet + index, &sent_packetnum, 4);
    index += 4;
    memcpy(packet + index, requested, 4 * number);

    return sendpacket(ip_port, packet, (number*4 + 4 + 4 + 3));
   
}


int send_data(IP_Port ip_port, uint32_t packet_num, char * data, uint32_t length)
{
    if(length > PDATA_SIZE)
    {
            return -1;
    }
    char packet[1 + 4 + PDATA_SIZE];
    
    packet[0] = 18;
    memcpy(packet + 1, &packet_num, 4);
    memcpy(packet + 5, data, length);
    return sendpacket(ip_port, packet, 1 + 4 + length);
}


//END of packet sending functions

//get connection id from IP_Port
//return -1 if there are no connections like we are looking for
//return id
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
uint32_t randtable[6][256];


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

//Packet handling functions
//One to handle each type of packets we recieve
//return 0 if handled correctly, 1 if packet is bad.
int handle_handshake(char * packet, uint32_t length, IP_Port source)
{
    if(length != (1 + 4 + 4))
    {
            return 1;
    }
    uint32_t handshake_id1, handshake_id2;
    memcpy(&handshake_id1, packet + 1, length);
    memcpy(&handshake_id2, packet + 5, length);
    
    if(handshake_id2 == 0)
    {
        send_handshake(source, handshake_id1, handshake_id(source));
        return 0;
    }
    int connection = getconnection_id(source);
    if(connection != 1)
    {
        return 0;
    }
    if(handshake_id1 == connections[connection].recv_packetnum)//if handshake_id1 is what we sent previously.
    {
        connections[connection].status = 2;
    }
    return 0;

}


handle_SYNC(char * packet, uint32_t length, IP_Port source)
{
    if(length < 4 + 4 + 3)
    {
        return 1;
    }
    if(length > (MAX_PACKET_NUM*4 + 4 + 4 + 3) || 
    ((length - 4 - 4 - 3) % 4) != 0)
    {
        return 1;
    }
    uint32_t reqpackets[MAX_PACKET_NUM];
    int connection = getconnection_id(source);
    char type;
    uint8_t counter;
    uint32_t recv_packetnum, sent_packetnum;
    uint32_t requested[MAX_PACKET_NUM];
    int16_t index = 2;
    
    memcpy(&counter, packet + index, 1);
    index += 1;
    memcpy(&recv_packetnum, packet + index, 4);
    index += 4;
    memcpy(&sent_packetnum,packet + index,  4);
    index += 4;
    
    //memcpy(requested, packet + index, 4 * number);
    
    
    if(connection == -1) //we are not connected to the person who sent us that packet
    {
        if(handshake_id(source) == recv_packetnum)
        {
            //TODO: handle new inbound connection
        }
        else
        {
        return 1;
        }
    }
    if(connections[connection].status == 2) //we have just recieved our first SYNC packet from the other.
    {
        if(connections[connection].recv_packetnum == recv_packetnum &&
        connections[connection].sent_packetnum == sent_packetnum)
        {
                connections[connection].status = 3;
                connections[connection].counter = counter + 1;
                connections[connection].last_recv = current_time();
        }
        
    }
    if(connections[connection].status == 3) //we are connected and the other person just sent us a SYNC packet
    {
        
        //TODO: finish this function.
        
        
    }
    
}


handle_data(char * packet, uint32_t length, IP_Port source)
{
    
    
    
}

//END of packet handling functions


//if we receive a Lossless_UDP packet we call this function so it can be handled.
//Return 0 if packet is handled correctly.
//return 1 if it didn't handle the packet or if the packet was shit.
int LosslessUDP_handlepacket(char * packet, uint32_t length, IP_Port source)
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


//Call this function a couple times per second
//It's the main loop.
void doLossless_UDP()
{
    
    
}