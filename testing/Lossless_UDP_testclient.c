/* Lossless_UDP testclient
 * A program that connects and sends a file using our lossless UDP algorithm.
 * NOTE: this program simulates a 33% packet loss.
 * 
 * Best used in combination with Lossless_UDP_testserver
 * 
 * Compile with: gcc -O2 -Wall -o testclient ../core/network.c ../core/Lossless_UDP.c Lossless_UDP_testclient.c
 * 
 * Command line arguments are the ip and port to connect and send the file to.
 * EX: ./testclient 127.0.0.1 33445 filename.txt
 */

#include "../core/network.h"
#include "../core/Lossless_UDP.h"

#ifdef WIN32

#define c_sleep(x) Sleep(1*x)

#else
#include <unistd.h>
#include <arpa/inet.h>
#define c_sleep(x) usleep(1000*x)

#endif


#define PORT 33446

void printpacket(uint8_t * data, uint32_t length, IP_Port ip_port)
{
    uint32_t i;
    printf("UNHANDLED PACKET RECEIVED\nLENGTH:%u\nCONTENTS:\n", length);
    printf("--------------------BEGIN-----------------------------\n");
    for(i = 0; i < length; i++)
    {
        if(data[i] < 16)
            printf("0");
        printf("%hhX",data[i]);
    }
    printf("\n--------------------END-----------------------------\n\n\n");
}

void printip(IP_Port ip_port)
{
    printf("\nIP: %u.%u.%u.%u Port: %u",ip_port.ip.c[0],ip_port.ip.c[1],ip_port.ip.c[2],ip_port.ip.c[3],ntohs(ip_port.port));
}
/*
void printpackets(Data test)
{
    int i;
    if(test.size == 0)
        return;
    printf("SIZE: %u\n", test.size);
    for(i =0; i < test.size; i++)
    {
        printf("%hhX", test.data[i]);
    }
    printf("\n");
}

void printconnection(int connection_id)
{
    printf("--------------------BEGIN---------------------\n");
    IP_Port ip_port = connections[connection_id].ip_port;
    printf("IP: %u.%u.%u.%u Port: %u\n",ip_port.ip.c[0],ip_port.ip.c[1],ip_port.ip.c[2],ip_port.ip.c[3],ntohs(ip_port.port));
    printf("status: %u, inbound: %u, SYNC_rate: %u\n", connections[connection_id].status, 
    connections[connection_id].inbound, connections[connection_id].SYNC_rate);
    printf("data rate: %u, last sync: %llu, last sent: %llu, last recv: %llu \n", connections[connection_id].data_rate, 
    connections[connection_id].last_SYNC, connections[connection_id].last_sent, connections[connection_id].last_recv);
    int i;
    for(i =0; i < MAX_QUEUE_NUM; i++)
    {
        printf(" %u ",i);
        printpackets(connections[connection_id].sendbuffer[i]);
    }
    for(i =0; i < MAX_QUEUE_NUM; i++)
    {
        printf(" %u ",i);
        printpackets(connections[connection_id].recvbuffer[i]);
    }
    Data sendbuffer[MAX_QUEUE_NUM];
    Data recvbuffer[MAX_QUEUE_NUM];
    printf("recv_num: %u, orecv_num: %u, sent_packetnum %u, osent_packetnum: %u, successful_sent: %u, successful_read: %u\n", 
    connections[connection_id].recv_packetnum, 
    connections[connection_id].orecv_packetnum, connections[connection_id].sent_packetnum, connections[connection_id].osent_packetnum,
    connections[connection_id].successful_sent,
    connections[connection_id].successful_read);
    
    printf("req packets: \n");
    for(i = 0; i < BUFFER_PACKET_NUM; i++)
    {
            printf(" %u ", connections[connection_id].req_packets[i]);
    }
    printf("\nNumber: %u recv_counter: %u, send_counter: %u\n", connections[connection_id].num_req_paquets,
    connections[connection_id].recv_counter, connections[connection_id].send_counter);

    printf("--------------------END---------------------\n");
    
}
*/
//recieve packets and send them to the packethandler
//run doLossless_UDP(); 
void Lossless_UDP()
{
    IP_Port ip_port;
    uint8_t data[MAX_UDP_PACKET_SIZE];
    uint32_t length;
    while(receivepacket(&ip_port, data, &length) != -1)
    {
        printf("packet with length: %u\n", length);
        //if(rand() % 3 != 1)//add packet loss
       // {    
            if(LosslessUDP_handlepacket(data, length, ip_port))
            {
                    printpacket(data, length, ip_port);
            }
            else
            {
                //printconnection(0);
                 printf("Received handled packet with length: %u\n", length);
            }
       // }
    }
    
    doLossless_UDP();   
    
}


int main(int argc, char *argv[])
{
    if (argc < 4) 
    {
        printf("usage: %s ip port filename\n", argv[0]);
        exit(0);
    }
    
    uint8_t buffer[512];
    int read;
    
    FILE *file = fopen(argv[3], "rb");
    if ( file==NULL ){return 1;}
    
    
    //initialize networking
    //bind to ip 0.0.0.0:PORT
    IP ip;
    ip.i = 0;
    init_networking(ip, PORT);
    perror("Initialization");
    IP_Port serverip;
    serverip.ip.i = inet_addr(argv[1]);
    serverip.port = htons(atoi(argv[2]));
    printip(serverip);
    int connection = new_connection(serverip);
    uint64_t timer = current_time();
    while(1)
    {
       // printconnection(connection);
        Lossless_UDP();
        if(is_connected(connection) == 3)
        {
            printf("Connecting took: %llu us\n", (unsigned long long)(current_time() - timer));
            break;
        }
        if(is_connected(connection) == 0)
        {
            printf("Connection timeout after: %llu us\n", (unsigned long long)(current_time() - timer));
            return 1;
        }
        c_sleep(1);
    }
    timer = current_time();
    
    
    //read first part of file
    read = fread(buffer, 1, 512, file);
    
    while(1)
    {
        //printconnection(connection);
        Lossless_UDP();
        if(is_connected(connection) == 3)
        {
            
            if(write_packet(connection, buffer, read))
            {
               //printf("Wrote data.\n");
                read = fread(buffer, 1, 512, file);

            }
            //printf("%u\n", sendqueue(connection));
            if(sendqueue(connection) == 0)
            {
                if(read == 0)
                {
                    printf("Sent file successfully in: %llu us\n", (unsigned long long)(current_time() - timer));
                    break;
                }
            }
        }
        else
        {
            printf("Connecting Lost after: %llu us\n", (unsigned long long)(current_time() - timer));
            return 0;
        }
        //c_sleep(1);
    }
        
    return 0;
}