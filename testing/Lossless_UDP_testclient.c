/* Lossless_UDP testclient
 * A program that connects and sends a file using our lossless UDP algorithm.
 * 
 * Best used in combination with Lossless_UDP_testserver
 * 
 * Compile with: gcc -O2 -Wall -o test ../core/network.c ../core/Lossless_UDP.c Lossless_UDP_testclient.c
 * 
 * Command line arguments are the ip and port to cennect and send the file to.
 * EX: ./test 127.0.0.1 33445 filename.txt
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

void printpacket(char * data, uint32_t length, IP_Port ip_port)
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


int main(int argc, char *argv[])
{
    if (argc < 4) 
    {
        printf("usage: %s ip port filename\n", argv[0]);
        exit(0);
    }
    
    char buffer[128];
    int read;
    
    FILE *file = fopen(argv[3], "rb");
    if ( file==NULL ){return 1;}
    
    
    //initialize networking
    //bind to ip 0.0.0.0:PORT
    IP ip;
    ip.i = 0;
    init_networking(ip, PORT);
    perror("Initialization");
    
    IP_Port serverip = {{{inet_addr(argv[1])}}, htons(atoi(argv[2]))};
    int connection = new_connection(serverip);
    uint64_t timer = current_time();
    while(1)
    {

        if(is_connected(connection) == 3)
        {
            printf("Connecting took: %llu us", (unsigned long long)(current_time() - timer));
            break;
        }
        if(is_connected(connection) == 0)
        {
            printf("Connection timeout after: %llu us", (unsigned long long)(current_time() - timer));
            break;
        }
        c_sleep(1);
    }
    timer = current_time();
    
    IP_Port ip_port;
    char data[MAX_UDP_PACKET_SIZE];
    uint32_t length;
    
    //read first part of file
    read = fread(buffer, 1, 128, file);
    
    while(1)
    {
        while(recievepacket(&ip_port, data, &length) != -1)
        {
            if(LosslessUDP_handlepacket(data, length, ip_port))
            {
                    printpacket(data, length, ip_port);
            }
            else
            {
                    printf("Received handled packet with length: %u\n", length);
            }
        }
        
        doLossless_UDP();
        
        if(is_connected(connection) == 1)
        {
            
            if(write_packet(connection, buffer, read))
            {
                read = fread(buffer, 1, 128, file);
            }
            if(sendqueue(connection) == 0)
            {
                if(read == 0)
                {
                    printf("Sent file successfully in: %llu us", (unsigned long long)(current_time() - timer));
                    break;
                }
            }
        }
        else
        {
            printf("Connecting Lost after: %llu us", (unsigned long long)(current_time() - timer));
        }
        c_sleep(1);
    }
        
    return 0;
}