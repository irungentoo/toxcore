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

#ifndef VANILLA_NACL
#include <sodium.h>
#else
#include <randombytes.h>
#endif

/* You can change those but be mindful */
#define PEERCOUNT       10
#define CHATCOUNT       3
#define PEERSPERCHAT    (PEERCOUNT/CHATCOUNT)

void idle_cylce(DHT**peers, int peercount)
{
    int j;
    for (j=0; j<peercount; j++)
    {
        networking_poll(peers[j]->net);
        do_DHT(peers[j]);
        // TODO: do we need do_net_crypto?
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

/* TODO: this looks ugly by now */
void basicannouncetest()
{
    /* The design is the following:
     * we have 10 tox instances, they form 3 chats of 3 members
     * the 10ths then proceeds to query the list of chat's participants */
    IP localhost;
    DHT *peers[PEERCOUNT];
    uint8_t pubkeys[PEERCOUNT*crypto_sign_PUBLICKEYBYTES];
    uint8_t seckeys[PEERCOUNT*crypto_sign_SECRETKEYBYTES];
    int i,j;
    
    /* Set ip to IPv6 loopback. TODO: IPv4 fallback? */
    ip_init(&localhost, 1);
    localhost.ip6.uint8[15]=1;
    
    /* Init the nodes */
    printf("Nodes generated:\n");
    for (i=0; i<PEERCOUNT; i++)
    {
        peers[i]=new_DHT(new_networking(localhost, TOX_PORTRANGE_FROM+i));
        crypto_sign_keypair(&pubkeys[i*crypto_sign_PUBLICKEYBYTES], &seckeys[i*crypto_sign_SECRETKEYBYTES]);
        printf("%s localhost6:%d%s", id_toa(peers[i]->self_public_key), peers[i]->net->port, (i%PEERSPERCHAT==2)?"\n---\n":"\n");
    }
    printf("\n");
    
    /* For simplicity sake, one big array */
    uint8_t chatids[CLIENT_ID_SIZE*CHATCOUNT];
    
    randombytes_buf((void*)chatids, CLIENT_ID_SIZE*CHATCOUNT);
    
    printf("Chats generated:\n");
    for (i=0; i<CHATCOUNT; i++)
        printf("%s\n",id_toa(&chatids[CLIENT_ID_SIZE*i]));
    printf("\n");
    
    /* Bootstrapping DHTs*/
    printf("Bootstrapping everybody from eachother\n");
    for (i=0; i<PEERCOUNT; i++)
    {
        DHT* target = peers[ i>=(PEERCOUNT-1)? 0 : i+1 ];
        IP_Port ip_port;
        ip_copy(&ip_port.ip, &localhost);
        ip_port.port = target->net->port;
        uint8_t *key = target->self_public_key;
        
        DHT_bootstrap(peers[i], ip_port, key);
    }
    
    /* Announcing chat presence */
    printf("Waiting until every DHT gets a full close client list\n");
    for (;;)
    {
        /* TODO: work out a situation when node count > LCLIENT_LIST */
        idle_cylce(peers, PEERCOUNT);
        
        int numconnected=0;
        for (i=0;i<PEERCOUNT;i++)
            numconnected+=DHT_connectiondegree(peers[i]);
        if (numconnected==PEERCOUNT*(PEERCOUNT-1))
            break;
        /* TODO: busy wait might be slightly more efficient here */
        usleep(50000);
    }
    for (i=0;i<9;i++)
    {
        uint8_t extkey[CLIENT_ID_EXT_SIZE];
        id_copy2(extkey, peers[i]->self_public_key, 1);
        id_copy2(extkey, &pubkeys[i*crypto_sign_PUBLICKEYBYTES-CLIENT_ID_SIZE], 2);
        if (initiate_gc_announce_request(peers[i], extkey, &seckeys[i*crypto_sign_SECRETKEYBYTES], &chatids[CLIENT_ID_SIZE*(i/PEERSPERCHAT)])<0)
        {
            /* TODO: change to check's wrappers when moving into auto_tests */
            printf("Announcing failure");
            goto cleanup;
        }
    }
    
    printf("Waiting 5 seconds before sending requests\n");
    idle_n_secs(5, peers, PEERCOUNT);
#if 0
    /* Requesting chat lists */
    for (i=0; i<CHATCOUNT; i++)
    {
        /* The last node gets to ask everybody */
        Node_format clnode;
        get_closest_known_node(peers[9], &chatids[CLIENT_ID_SIZE*i], &clnode, 0, 1, 1);
        printf("Closest node second iteration: %s\n", id_toa(clnode.client_id));
        if (get_gc_announced_nodes_request(peers[9], clnode.ip_port, clnode.client_id, &chatids[CLIENT_ID_SIZE*i])<0)
        {
            /* TODO: change to check's wrappers when moving into auto_tests */
            printf("Requesting nodes failure");
            goto cleanup;
        }
    }

    printf("Waiting 10 seconds before checking\n");
    idle_n_secs(10, peers, PEERCOUNT);
    
    /* Inspecting the catch */
    for (i=0; i<CHATCOUNT; i++)
    {
        Node_format nodes[MAX_ANNOUNCED_NODES]; 
        int nodes_found=get_announced_nodes(peers[9]->announce, &chatids[CLIENT_ID_SIZE*i], nodes, 1);
        printf("Chat %s, found %d nodes:\n", id_toa(&chatids[CLIENT_ID_SIZE*i]), nodes_found);
        for (j=0; j<nodes_found; j++)
            printf("\t Node %s at %s:%d\n", id_toa(nodes[j].client_id), ip_ntoa(&nodes[j].ip_port.ip), nodes[j].ip_port.port);
    }
#endif
    cleanup:
    /* Deinit the nodes */
    for (i=0; i<PEERCOUNT; i++)
        kill_DHT(peers[i]);
}

int main()
{
    basicannouncetest();
    return 0;
}
