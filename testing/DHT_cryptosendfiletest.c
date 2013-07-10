/* DHT cryptosendfiletest
 * 
 * This program sends or recieves a friend request.
 * 
 * it also sends the encrypted data from a file to another client.
 * Receives the file data that that client sends us.
 * 
 * NOTE: this program simulates 33% packet loss.
 * 
 * This is how I compile it: gcc -O2 -Wall -o test ../core/Lossless_UDP.c ../core/network.c ../core/net_crypto.c ../core/DHT.c ../nacl/build/$HOSTNAME/lib/amd64/* DHT_cryptosendfiletest.c 
 *
 * 
 * Command line arguments are the ip and port of a node (for bootstrapping).
 * 
 * Saves all received data to: received.txt
 * 
 * EX: ./test 127.0.0.1 33445 filename.txt
 */
#include "../core/network.h"
#include "../core/DHT.h"
#include "../core/net_crypto.h"

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


//horrible function from one of my first C programs.
//only here because I was too lazy to write a proper one.
unsigned char * hex_string_to_bin(char hex_string[])
{
    unsigned char * val = malloc(strlen(hex_string));
    char * pos = hex_string;
    int i=0;
    while(i < strlen(hex_string))
    {
        sscanf(pos,"%2hhx",&val[i]);
        pos+=2;
        i++;
    }
    return val;
}

uint8_t self_public_key[crypto_box_PUBLICKEYBYTES];

int main(int argc, char *argv[])
{
    if (argc < 4) {
        printf("usage %s ip port filename(of file to send)\n", argv[0]);
        exit(0);
    }
    new_keys();
    printf("OUR ID: ");
    uint32_t i;
    for(i = 0; i < 32; i++)
    {
        if(self_public_key[i] < 16)
            printf("0");
        printf("%hhX",self_public_key[i]);
    }
    printf("\n");
    
    memcpy(self_client_id, self_public_key, 32);
    
    char temp_id[128];
    printf("Enter the client_id of the friend to connect to (32 bytes HEX format):\n");
    scanf("%s", temp_id);
    
    uint8_t friend_id[32];
    memcpy(friend_id, hex_string_to_bin(temp_id), 32);
    
    
    //memcpy(self_client_id, "qqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqq", 32);
    

    DHT_addfriend(friend_id);
    IP_Port friend_ip;
    int connection = -1;
    int inconnection = -1;
    
    uint8_t acceptedfriend_public_key[crypto_box_PUBLICKEYBYTES];
    int friendrequest = -1;
    uint8_t request_data[512];
    
    //initialize networking
    //bind to ip 0.0.0.0:PORT
    IP ip;
    ip.i = 0;
    init_networking(ip, PORT);
    initNetCrypto();
    
    

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
    FILE *file1 = fopen(argv[3], "rb");
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
        friend_ip = DHT_getfriendip(friend_id);
        if(friend_ip.ip.i != 0)
        {
            if(connection == -1 && friendrequest == -1)
            {
                printf("Sending friend request to peer:");
                printip(friend_ip);
                friendrequest = send_friendrequest(friend_id, friend_ip,(uint8_t *) "Hello World", 12);
                //connection = crypto_connect((uint8_t *)friend_id, friend_ip);
                //connection = new_connection(friend_ip);
            }
            if(check_friendrequest(friendrequest) == 1)
            {
                printf("Started connecting to friend:");
                connection = crypto_connect(friend_id, friend_ip);
            }
        }
        if(inconnection == -1)
        {
            uint8_t secret_nonce[crypto_box_NONCEBYTES];
            uint8_t public_key[crypto_box_PUBLICKEYBYTES];
            uint8_t session_key[crypto_box_PUBLICKEYBYTES];
            inconnection = crypto_inbound(public_key, secret_nonce, session_key);
            inconnection = accept_crypto_inbound(inconnection, acceptedfriend_public_key, secret_nonce, session_key);
            //inconnection = incoming_connection();
            if(inconnection != -1)
            {
                printf("Someone connected to us:\n");
               // printip(connection_ip(inconnection));
            }
        }
        if(handle_friendrequest(acceptedfriend_public_key, request_data) > 1)
        {
            printf("RECIEVED FRIEND REQUEST: %s\n", request_data);
        }

        //if someone connected to us write what he sends to a file
        //also send him our file.
        if(inconnection != -1)
        {
            if(write_cryptpacket(inconnection, buffer1, read1))
            {
                printf("Wrote data1.\n");
                read1 = fread(buffer1, 1, 128, file1);
            }
            read2 = read_cryptpacket(inconnection, buffer2);
            if(read2 != 0)
            {
                printf("Received data1.\n");
                if(!fwrite(buffer2, read2, 1, file2))
                {
                        printf("file write error1\n");
                }
                if(read2 < 128)
                {
                    printf("Closed file1 %u\n", read2);
                    fclose(file2);
                }
            }
            else if(is_cryptoconnected(inconnection) == 4)//if buffer is empty and the connection timed out.
            {
                crypto_kill(inconnection);
            }
        }
        //if we are connected to a friend send him data from the file.
        //also put what he sends us in a file.
        if(is_cryptoconnected(connection) >= 3)
        {
            if(write_cryptpacket(0, buffer1, read1))
            {
                printf("Wrote data2.\n");
                read1 = fread(buffer1, 1, 128, file1);
            }
            read2 = read_cryptpacket(0, buffer2);
            if(read2 != 0)
            {
                printf("Received data2.\n");
                if(!fwrite(buffer2, read2, 1, file2))
                {
                        printf("file write error2\n");
                }
                if(read2 < 128)
                {
                    printf("Closed file2 %u\n", read2);
                    fclose(file2);
                }
            }
            else if(is_cryptoconnected(connection) == 4)//if buffer is empty and the connection timed out.
            {
                crypto_kill(connection);
            }
        }
        doDHT();
        doLossless_UDP();
        doNetCrypto();
        //print_clientlist();
        //print_friendlist();
        //c_sleep(300);
        c_sleep(1);
    }
    
    shutdown_networking();
    return 0;   
}