/* DHT sendfiletest
 * 
 * Sends the data from a file to another client.
 * Receives the file data that that client sends us.
 * 
 * NOTE: this program simulates 33% packet loss.
 * 
 * Compile with: gcc -O2 -Wall -o test ../core/DHT.c ../core/network.c ../core/Lossless_UDP.c DHT_sendfiletest.c
 * 
 * Command line arguments are the ip and port of a node (for bootstrapping), the 
 * client_id (32 bytes) of the friend you want to send the data in filename to and
 * the client_id this node will take.
 * 
 * Saves all received data to: received.txt
 * 
 * EX: ./test 127.0.0.1 33445 ABCDEFGHIJKLMNOPQRSTUVWXYZabcdef filename.txt ABCDEFGHIJKLMNOPQRSTUVWXYZabcdeg
 */
#include "../core/network.h"
#include "../core/DHT.h"
#include "../core/Lossless_UDP.h"

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

void printip(IP_Port ip_port)
{
    printf("\nIP: %u.%u.%u.%u Port: %u\n",ip_port.ip.c[0],ip_port.ip.c[1],ip_port.ip.c[2],ip_port.ip.c[3],ntohs(ip_port.port));
}

int main(int argc, char *argv[])
{
    //memcpy(self_client_id, "qqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqq", 32);
    
    if (argc < 6) {
        printf("usage %s ip port client_id(of friend to find ip_port of) filename(of file to send) client_id(ours)\n", argv[0]);
        exit(0);
    }
    DHT_addfriend((uint8_t *)argv[3]);
    IP_Port friend_ip;
    int connection = -1;
    int inconnection = -1;
    
    //initialize networking
    //bind to ip 0.0.0.0:PORT
    IP ip;
    ip.i = 0;
    init_networking(ip, PORT);
    
    memcpy(self_client_id, argv[5], 32);
    

    perror("Initialization");
    IP_Port bootstrap_ip_port;
    bootstrap_ip_port.port = htons(atoi(argv[2]));
    bootstrap_ip_port.ip.i = inet_addr(argv[1]);
    DHT_bootstrap(bootstrap_ip_port);
    
    IP_Port ip_port;
    uint8_t data[MAX_UDP_PACKET_SIZE];
    uint32_t length;
    
    uint8_t buffer1[128];
    int read1 = 0;
    uint8_t buffer2[128];
    int read2 = 0;
    FILE *file1 = fopen(argv[4], "rb");
    if ( file1==NULL ){printf("Error opening file.\n");return 1;}
    FILE *file2 = fopen("received.txt", "wb");
    if ( file2==NULL ){return 1;}
    read1 = fread(buffer1, 1, 128, file1);
    
    while(1)
    {

        while(receivepacket(&ip_port, data, &length) != -1)
        {
            if(rand() % 3 != 1)//simulate packet loss
            {
                if(DHT_handlepacket(data, length, ip_port) && LosslessUDP_handlepacket(data, length, ip_port))
                {
                    //if packet is not recognized
                    printf("Received unhandled packet with length: %u\n", length);
                }
                else
                {
                    printf("Received handled packet with length: %u\n", length);
                }
            }
        }
        friend_ip = DHT_getfriendip((uint8_t *)argv[3]);
        if(friend_ip.ip.i != 0)
        {
            if(connection == -1)
            {
                printf("Started connecting to friend:");
                printip(friend_ip);
                connection = new_connection(friend_ip);
            }
        }
        if(inconnection == -1)
        {
            inconnection = incoming_connection();
            if(inconnection != -1)
            {
                printf("Someone connected to us:");
                printip(connection_ip(inconnection));
            }
        }
        //if someone connected to us write what he sends to a file
        //also send him our file.
        if(inconnection != -1)
        {
            if(write_packet(inconnection, buffer1, read1))
            {
                printf("Wrote data.\n");
                read1 = fread(buffer1, 1, 128, file1);
            }
            read2 = read_packet(inconnection, buffer2);
            if(read2 != 0)
            {
                printf("Received data.\n");
                if(!fwrite(buffer2, read2, 1, file2))
                {
                        printf("file write error\n");
                }
                if(read2 < 128)
                {
                    fclose(file2);
                }
            } 
        }
        //if we are connected to a friend send him data from the file.
        //also put what he sends us in a file.
        if(is_connected(connection) == 3)
        {
            if(write_packet(0, buffer1, read1))
            {
                printf("Wrote data.\n");
                read1 = fread(buffer1, 1, 128, file1);
            }
            read2 = read_packet(0, buffer2);
            if(read2 != 0)
            {
                printf("Received data.\n");
                if(!fwrite(buffer2, read2, 1, file2))
                {
                        printf("file write error\n");
                }
                if(read2 < 128)
                {
                    fclose(file2);
                }
            } 
        }
        doDHT();
        doLossless_UDP();
        //print_clientlist();
        //print_friendlist();
        //c_sleep(300);
        c_sleep(1);
    }
    
    shutdown_networking();
    return 0;   
}