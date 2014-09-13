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

#define min(a,b) ((a)>(b)?(b):(a))

/* You can change those but be mindful */
#define PEERCOUNT       20
#define CHATCOUNT       1 

typedef struct Peer
{
    DHT * dht;
    uint8_t pk[EXT_PUBLIC_KEY];
    uint8_t sk[EXT_SECRET_KEY];
} Peer;


void idle_cylce(Peer *peers, int peercount)
{
    int j;
    for (j=0; j<peercount; j++)
    {
        networking_poll(peers[j].dht->net);
        do_DHT(peers[j].dht);
    }
 
}

void idle_n_secs(int n, Peer *peers, int peercount)
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
    Peer peers[PEERCOUNT];

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

    printf("Bootstrapping everybody from eachother\n");
    for (i=0; i<PEERCOUNT; i++)
    {
        DHT* target = peers[ i>=(PEERCOUNT-1)? 0 : i+1 ].dht;
        IP_Port ip_port;
        ip_copy(&ip_port.ip, &localhost);
        ip_port.port = target->net->port;
        uint8_t *key = target->self_public_key;
        
        DHT_bootstrap(peers[i].dht, ip_port, key);
    }

    printf("Waiting until every DHT gets a full close client list\n");
    for (;;)
    {
        idle_cylce(peers, PEERCOUNT);
        
        int numconnected=0;
        for (i=0;i<PEERCOUNT;i++)
            numconnected+=DHT_isconnected(peers[i].dht);
        if (numconnected==PEERCOUNT*min(PEERCOUNT-1,LCLIENT_LIST))
            break;
        /* TODO: busy wait might be slightly more efficient here */
        usleep(50000);
    }

    printf("Network is connested\n");


}

int main()
{
    basicannouncetest();
    return 0;
}