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

//initial amount of sync/hanshake packets to send per second.
#define SYNC_RATE 5

//send rate of sync packets when data is being sent/recieved.
#define DATA_SYNC_RATE 20

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
    uint64_t last_sent; //time at which our last data or handshake packet was sent.
    uint64_t last_recv; //time at which we last recieved something from the other
    Data sendbuffer[MAX_QUEUE_NUM];//packet send buffer.
    Data recvbuffer[MAX_QUEUE_NUM];//packet recieve buffer.
    uint32_t handshake_id1;
    uint32_t handshake_id2;
    uint32_t recv_packetnum; //number of data packets recieved (also used as handshake_id1)
    uint32_t orecv_packetnum; //number of packets recieved by the other peer
    uint32_t sent_packetnum; //number of data packets sent
    uint32_t osent_packetnum; //number of packets sent by the other peer.
    uint32_t sendbuff_packetnum; //number of latest packet written onto the sendbuffer
    uint32_t successful_sent;//we know all packets before that number were successfully sent
    uint32_t successful_read;//packet number of last packet read with the read_packet function
    uint32_t req_packets[MAX_PACKET_NUM]; //list of currently requested packet numbers(by the other person)
    uint16_t num_req_paquets; //total number of currently requested packets(by the other person)
    uint8_t recv_counter;
    uint8_t send_counter;
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
            connections[i].ip_port = ip_port;
            connections[i].status = 1;
            connections[i].inbound = 0;
            connections[i].handshake_id1 = random_int();
            connections[i].SYNC_rate = SYNC_RATE;
            connections[i].data_rate = DATA_SYNC_RATE;
            connections[i].last_recv = current_time();
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
    uint32_t i;
    for(i = 0; i < MAX_CONNECTIONS; i++)
    {
        if(connections[i].status == 0)
        {
            connections[i].ip_port = ip_port;
            connections[i].status = 2;
            connections[i].inbound = 2;
            connections[i].SYNC_rate = SYNC_RATE;
            connections[i].data_rate = DATA_SYNC_RATE;
            connections[i].last_recv = current_time();
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
    
    return 0;
}

//return 0 if data could not be put in packet queue
//return 1 if data was put into the queue
int write_packet(int connection_id, char * data, uint32_t length)
{
    
    
    return 0;
}



//returns the number of packets in the queue waiting to be successfully sent.
int sendqueue(int connection_id)
{
    return connections[connection_id].sendbuff_packetnum - connections[connection_id].successful_sent;
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

//put the packet numbers the we are missing in requested and return the number
uint32_t missing_packets(int connection_id, uint32_t * requested)
{
    uint32_t number = 0;
    uint32_t i;
    for(i = connections[connection_id].recv_packetnum; i != connections[connection_id].osent_packetnum; i++ )
    {
        if(connections[connection_id].recvbuffer[i % MAX_QUEUE_NUM].size == 0)
        {
            memcpy(requested, &i, number);
            number++;
        }
    }
    return number;
    
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


int send_SYNC(uint32_t connection_id)
{
    
    char packet[(MAX_PACKET_NUM*4 + 4 + 4 + 2)];
    uint16_t index = 0;
    
    IP_Port ip_port = connections[connection_id].ip_port;
    uint8_t counter = connections[connection_id].send_counter;
    uint32_t recv_packetnum = connections[connection_id].recv_packetnum;
    uint32_t sent_packetnum = connections[connection_id].sent_packetnum;
    uint32_t requested[MAX_PACKET_NUM];
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
    memcpy(&handshake_id1, packet + 1, 4);
    memcpy(&handshake_id2, packet + 5, 4);
    if(handshake_id2 == 0)
    {
        send_handshake(source, handshake_id1, handshake_id(source));
        return 0;
    }
    int connection = getconnection_id(source);
    if(is_connected(connection) != 1)
    {
        return 1;
    }
    if(handshake_id1 == connections[connection].handshake_id1)//if handshake_id1 is what we sent previously.
    {
        connections[connection].status = 2;
        //NOTE:is this necessary?
        //connections[connection].handshake_id2 = handshake_id2;
        connections[connection].orecv_packetnum = handshake_id1;
        connections[connection].sent_packetnum = handshake_id1;
        connections[connection].osent_packetnum = handshake_id2;
        connections[connection].recv_packetnum = handshake_id2;
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
    if(length > (MAX_PACKET_NUM*4 + 4 + 4 + 2) || 
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
            connections[x].osent_packetnum = sent_packetnum;
            connections[x].recv_packetnum = sent_packetnum;
            
            return x;
        }
    }
    return -1;
}

//case 2:
int handle_SYNC2(int connection_id, uint8_t counter, uint32_t recv_packetnum, uint32_t sent_packetnum)
{
    if(recv_packetnum == connections[connection_id].orecv_packetnum && 
       sent_packetnum == connections[connection_id].osent_packetnum)
    {
        connections[connection_id].status =  3;
        connections[connection_id].recv_counter = counter;
        connections[connection_id].send_counter++;
        return 0;
    }
}
//case 3:
int handle_SYNC3(int connection_id, uint8_t counter, uint32_t recv_packetnum, uint32_t sent_packetnum, uint32_t * req_packets,
                 uint16_t number)
{
    uint8_t comp_counter = (connections[connection_id].recv_counter + 1);
    if((recv_packetnum - connections[connection_id].orecv_packetnum) < MAX_PACKET_NUM &&
       (sent_packetnum - connections[connection_id].osent_packetnum) < MAX_PACKET_NUM &&
        counter == comp_counter) //packet valid
    {
        connections[connection_id].orecv_packetnum = recv_packetnum;
        connections[connection_id].osent_packetnum = sent_packetnum;
        connections[connection_id].last_recv = current_time();
        connections[connection_id].recv_counter = counter;
        connections[connection_id].send_counter++;
        memcpy(connections[connection_id].req_packets, req_packets, 4 * number);
        connections[connection_id].num_req_paquets = number;
        return 0;
    }
    return 1;
}

int handle_SYNC(char * packet, uint32_t length, IP_Port source)
{

    if(!SYNC_valid(length))
    {
        return 1;   
    }
    int connection = getconnection_id(source);
    uint8_t counter;
    uint32_t recv_packetnum, sent_packetnum;
    uint32_t req_packets[MAX_PACKET_NUM];
    uint16_t number = (length - 4 - 4 - 2)/ 4;
    
    memcpy(&counter, packet + 1, 1);
    memcpy(&recv_packetnum, packet + 2, 4);
    memcpy(&sent_packetnum,packet + 6,  4);
    if(number != 0)
    {
        memcpy(req_packets, packet + 10,  4 * number);
    }
    if(connection == -1)
    {
        handle_SYNC1(source, recv_packetnum, sent_packetnum);
        return 0;
    }
    if(connections[connection].status ==  2)
    {
        handle_SYNC2(connection, counter, recv_packetnum, sent_packetnum);
        return 0;
    }
    if(connections[connection].status ==  3)
    {
        handle_SYNC3(connection, counter, recv_packetnum, sent_packetnum, req_packets, number);
    }    
    return 0;
}

int handle_data(char * packet, uint32_t length, IP_Port source)
{
    
}

//END of packet handling functions


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

//Send handshake requests
//TODO: optimize this.
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
        if( connections[i].status > 0 && (connections[i].last_recv + CONNEXION_TIMEOUT * 1000000UL) < temp_time)
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