/* DHT boostrap
 * 
 * A simple DHT boostrap server for tox.
 * 
 * Build command: gcc -O2 -Wall -D VANILLA_NACL -o bootstrap_server ../core/Lossless_UDP.c ../core/network.c ../core/net_crypto.c ../core/Messenger.c ../core/DHT.c ../nacl/build/${HOSTNAME%.*}/lib/amd64/{cpucycles.o,libnacl.a,randombytes.o} DHT_bootstrap.c
 * 
 */

#include "../core/DHT.h"


//Sleep function (x = milliseconds)
#ifdef WIN32
#define c_sleep(x) Sleep(1*x)
#else
#include <unistd.h>
#define c_sleep(x) usleep(1000*x)
#endif

#define PORT 33445



int main(int argc, char *argv[])
{
    new_keys();
    printf("Public key: ");
    uint32_t i;
    for(i = 0; i < 32; i++)
    {
        if(self_public_key[i] < 16)
            printf("0");
        printf("%hhX",self_public_key[i]);
    }
    printf("\n");
    //initialize networking
    //bind to ip 0.0.0.0:PORT
    IP ip;
    ip.i = 0;
    init_networking(ip, PORT);
    
    perror("Initialization");

    IP_Port ip_port;
    uint8_t data[MAX_UDP_PACKET_SIZE];
    uint32_t length;
    
    while(1)
    {   
        doDHT();
        
        while(receivepacket(&ip_port, data, &length) != -1)
        {
            DHT_handlepacket(data, length, ip_port);
        }
        c_sleep(1);
    }
    shutdown_networking();
    return 0;   
}