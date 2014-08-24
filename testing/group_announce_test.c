/* Basic group announcing testing
 * TODO: please add license and everything */

#include "../toxcore/tox.h"
#include "../toxcore/network.h"
#include "../toxcore/DHT.h"
#include "../toxcore/ping.h"
#include "../toxcore/util.h"
#include "../toxcore/group_announce.h"

#include <stdio.h>
#include <stdlib.h>

/* You can change those but be mindful */
#define PEERCOUNT       20
#define CHATCOUNT       1 

void idle_cylce(DHT**peers, int peercount)
{
    int j;
    for (j=0; j<peercount; j++)
    {
        networking_poll(peers[j]->net);
        do_DHT(peers[j]);
    }
 
}

void idle_n_secs(int n, DHT** peers, int peercount)
{
    int i,j;
    for (i=0; i<n*1000; i+=50) /* msecs */
    {
        idle_cylce(peers, peercount);
        usleep(50000); /* usecs */
    }
}

void basicannouncetest()
{

    IP localhost;

    struct Peer
    {
        DHT * dht;
        uint8_t pk[EXT_PUBLIC_KEY];
        uint8_t sk[EXT_SECRET_KEY];
    }   peers[PEERCOUNT];


    int i,j;
    
    /* Set ip to IPv6 loopback. TODO: IPv4 fallback? */
    ip_init(&localhost, 1);
    localhost.ip6.uint8[15]=1;
    
    printf("DHT public keys:\n"); 
    for (i=0; i<PEERCOUNT; i++)
    {
        peers[i].dht=new_DHT(new_networking(localhost, TOX_PORTRANGE_FROM+i));
        create_long_keypair(peers[i].pk, peers[i].sk);
        printf("%s, %d\n", id_toa(peers[i].dht->self_public_key), i);
    }


}

int main()
{
    basicannouncetest();
    return 0;
}