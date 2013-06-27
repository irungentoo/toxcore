/* DHT test
 * A file with a main that runs our DHT for testing.
 * 
 * Compile with: gcc -O2 -Wall -o test ../core/DHT.c ../core/network.c DHT_test.c
 * 
 * Command line arguments are the ip and port of a node and the client_id (32 bytes) of the friend you want to find the ip_port of
 * EX: ./test 127.0.0.1 33445 ABCDEFGHIJKLMNOPQRSTUVWXYZabcdef
 */
#include "../core/network.h"
#include "../core/DHT.h"

#include <string.h>

//Sleep function (x = milliseconds)
#ifdef WIN32

#define c_sleep(x) Sleep(1*x)

#else
#include <unistd.h>
#include <arpa/inet.h>
#define c_sleep(x) usleep(1000*x)

#endif

#define PORT 33445


void print_clientlist()
{
    uint32_t i, j;
    IP_Port p_ip;
    printf("___________________CLOSE________________________________\n");
    for(i = 0; i < 4; i++)
    {
        printf("ClientID: ");
        for(j = 0; j < 32; j++)
        {
            printf("%c", close_clientlist[i].client_id[j]);
        }
        p_ip = close_clientlist[i].ip_port;
        printf("\nIP: %u.%u.%u.%u Port: %u",p_ip.ip.c[0],p_ip.ip.c[1],p_ip.ip.c[2],p_ip.ip.c[3],ntohs(p_ip.port));
        printf("\nTimestamp: %u", close_clientlist[i].timestamp);
        printf("\nLast pinged: %u\n", close_clientlist[i].last_pinged);
    }  
}

void print_friendlist()
{
    uint32_t i, j, k;
    IP_Port p_ip;
    printf("_________________FRIENDS__________________________________\n");
    for(k = 0; k < num_friends; k++)
    {
        printf("FRIEND %u\n", k);
        printf("ID: ");
        for(j = 0; j < 32; j++)
        {
            printf("%c", friends_list[k].client_id[j]);
        }
        p_ip = getfriendip(friends_list[k].client_id);
        printf("\nIP: %u.%u.%u.%u:%u",p_ip.ip.c[0],p_ip.ip.c[1],p_ip.ip.c[2],p_ip.ip.c[3],ntohs(p_ip.port));

        printf("\nCLIENTS IN LIST:\n\n");
        
        for(i = 0; i < 4; i++)
        {
            printf("ClientID: ");
            for(j = 0; j < 32; j++)
            {
                if(0 <= friends_list[k].client_list[i].client_id[j] && friends_list[k].client_list[i].client_id[j] < 16)
                    printf("0");
                printf("%hhX", friends_list[k].client_list[i].client_id[j]);
            }
            p_ip = friends_list[k].client_list[i].ip_port;
            printf("\nIP: %u.%u.%u.%u:%u",p_ip.ip.c[0],p_ip.ip.c[1],p_ip.ip.c[2],p_ip.ip.c[3],ntohs(p_ip.port));
            printf("\nTimestamp: %u", friends_list[k].client_list[i].timestamp);
            printf("\nLast pinged: %u\n", friends_list[k].client_list[i].last_pinged);
        }
    }
}

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
    srand(time(NULL));
    int randdomnum = rand();
    memcpy(self_client_id, &randdomnum, 4);
    //memcpy(self_client_id, "qqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqq", 32);
    
    if (argc < 4) {
        printf("usage %s ip port client_id(of friend to find ip_port of)\n", argv[0]);
        exit(0);
    }
    addfriend(argv[3]);
    
    
    //initialize networking
    //bind to ip 0.0.0.0:PORT
    IP ip;
    ip.i = 0;
    init_networking(ip, PORT);

    perror("Initialization");
    IP_Port bootstrap_ip_port;
    bootstrap_ip_port.port = htons(atoi(argv[2]));
    //bootstrap_ip_port.ip.c[0] = 127;
    //bootstrap_ip_port.ip.c[1] = 0;
    //bootstrap_ip_port.ip.c[2] = 0;
    //bootstrap_ip_port.ip.c[3] = 1;
    bootstrap_ip_port.ip.i = inet_addr(argv[1]);
    bootstrap(bootstrap_ip_port);
    
    IP_Port ip_port;
    char data[MAX_UDP_PACKET_SIZE];
    uint32_t length;
    
    while(1)
    {
            
        doDHT();
        
        while(recievepacket(&ip_port, data, &length) != -1)
        {
            if(DHT_handlepacket(data, length, ip_port))
            {
                //unhandled packet
                printpacket(data, length, ip_port);
            }
            else
            {
                printf("Received handled packet with length: %u\n", length);
            }
        }
        print_clientlist();
        print_friendlist();
        c_sleep(300);
    }
    
    shutdown_networking();
    return 0;   
}