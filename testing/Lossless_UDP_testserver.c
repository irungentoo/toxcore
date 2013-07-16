/* Lossless_UDP testserver
 * A program that waits for a lossless UDP connection and then saves all the data recieved to a file.
 * NOTE: this program simulates a 33% packet loss.
 * 
 * Best used in combination with Lossless_UDP_testclient
 * 
 * Compile with: gcc -O2 -Wall -o testserver ../core/network.c ../core/Lossless_UDP.c Lossless_UDP_testserver.c
 * 
 * Command line argument is the name of the file to save what we recieve to.
 * EX: ./testserver filename1.txt
 */

#include "../core/network.h"
#include "../core/Lossless_UDP.h"

//Sleep function (x = milliseconds)
#ifdef WIN32

#define c_sleep(x) Sleep(1*x)

#else
#include <unistd.h>
#include <arpa/inet.h>
#define c_sleep(x) usleep(1000*x)

#endif


#define PORT 33445

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
        //if(rand() % 3 != 1)//add packet loss
        //{
            if(LosslessUDP_handlepacket(data, length, ip_port))
            {
                    printpacket(data, length, ip_port);
            }
            else
            {
                //printconnection(0);
                 printf("Received handled packet with length: %u\n", length);
            }
        //}
    }
    
    doLossless_UDP();   
    
}


int main(int argc, char *argv[])
{
    if (argc < 2) 
    {
        printf("usage: %s filename\n", argv[0]);
        exit(0);
    }
    
    uint8_t buffer[512];
    int read;
    
    FILE *file = fopen(argv[1], "wb");
    if ( file==NULL ){return 1;}
    
    
    //initialize networking
    //bind to ip 0.0.0.0:PORT
    IP ip;
    ip.i = 0;
    init_networking(ip, PORT);
    perror("Initialization");
    
    int connection;
    uint64_t timer = current_time();
    
    
    while(1)
    {
        Lossless_UDP();
        connection = incoming_connection();
        if(connection != -1)
        {
            if(is_connected(connection) == 2)
            {
                printf("Recieved the connection.\n");
                
            }
            break;
        }
        c_sleep(1);
    }
    
    timer = current_time();
    
    while(1)
    {
        //printconnection(0);
        Lossless_UDP();
        if(is_connected(connection) >= 2)
        {
            kill_connection_in(connection, 3000000);
            read = read_packet(connection, buffer);
            if(read != 0)
            {
               // printf("Recieved data.\n");
                if(!fwrite(buffer, read, 1, file))
                {
                        printf("file write error\n");
                }
            }
        }
        if(is_connected(connection) == 4)
        {
            printf("Connecting Lost after: %llu us\n", (unsigned long long)(current_time() - timer));
            fclose(file);
            return 1;
        }
        c_sleep(1);
    }
        
    return 0;
}