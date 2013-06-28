/* Lossless_UDP testserver
 * A program that waits for a lossless UDP connection and then saves all the data recieved to a file.
 * 
 * Best used in combination with Lossless_UDP_testclient
 * 
 * Compile with: gcc -O2 -Wall -o test ../core/network.c ../core/Lossless_UDP.c Lossless_UDP_testserver.c
 * 
 * Command line argument is the name of the file to save what we recieve to.
 * EX: ./test filename1.txt
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
    if (argc < 2) 
    {
        printf("usage: %s filename\n", argv[0]);
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
    
    int connection;
    uint64_t timer = current_time();
    
    IP_Port ip_port;
    char data[MAX_UDP_PACKET_SIZE];
    uint32_t length;
    
    while(1)
    {
        connection = incoming_connection();
        if(connection != -1)
        {
            if(is_connected(connection) == 3)
            {
                printf("Recieved the connection.");
            }
            break;
        }
        c_sleep(1);
    }
    
    timer = current_time();
    
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
            read = read_packet(connection, buffer);
            if(read != 0)
            {
                if(!fwrite(buffer, read, 1, file))
                {
                        printf("file write error\n");
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