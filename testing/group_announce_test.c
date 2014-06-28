/* Basic group announcing testing
 * TODO: please add license and everything */

#include "../toxcore/tox.h"
#include "../toxcore/network.h"
#include "../toxcore/DHT.h"
#include "../toxcore/ping.h"
#include "../toxcore/util.h"
#include "../toxcore/group_announce.h"
#include "../toxcore/Messenger.h"

#include <stdio.h>
#include <stdlib.h>

#ifndef VANILLA_NACL
#include <sodium.h>
#else
#include <randombytes.h>
#endif

void idle_cylce(Tox**peers, int peercount)
{
    int j;
    for (j=0; j<peercount; j++)
        tox_do(peers[j]);
 
}

void idle_n_secs(int n, Tox** peers, int peercount)
{
    int i,j;
    for (i=0; i<n*1000; i+=50) /* msecs */
    {
        idle_cylce(peers, peercount);
        usleep(50000); /* usecs */
    }
}

/* TODO: probably include that to DHT.c */
void get_closest_known_node(DHT* dht, uint8_t *client_id, Node_format *out)
{   
    /* Finding the closest peer to the chat id */
    static Node_format nodes[MAX_SENT_NODES];
    Node_format *closest_node=NULL;
    int nclosest, j;
    nclosest=get_close_nodes(dht, client_id, nodes, 0, 1, 1);
    
    /* WARNING: keep in mind that DHT nodes have separate temporary ids */
    for (j=0; j<nclosest; j++)
    {
        /* printf("Found node: %s %s:%d\n",id_toa(nodes[j].client_id),ip_ntoa(&nodes[j].ip_port.ip),nodes[j].ip_port.port); */
        if (closest_node==NULL || (id_closest(client_id, closest_node->client_id, nodes[j].client_id)==2))
            closest_node=&nodes[j];
    }
    
    /* printf("Closest node: %s\n", id_toa(closest_node->client_id)); */
    
    /* Copy over to the result */
    id_copy(out->client_id, closest_node->client_id);
    memcpy(&out->ip_port, &closest_node->ip_port, sizeof(IP_Port));
}

/* TODO: this looks ugly by now */
void basicannouncetest()
{
    /* The design is the following:
     * we have 10 tox instances, they form 3 chats of 3 members
     * the 10ths then proceeds to query the list of chat's participants */
    Tox *peers[10];
    int i,j;
    
    /* Init the nodes */
    printf("Nodes generated:\n");
    uint8_t clientids[(CLIENT_ID_SIZE+6)*10];
    for (i=0; i<10; i++)
    {
        peers[i]=tox_new(TOX_ENABLE_IPV6_DEFAULT);
        
        tox_get_address(peers[i],&clientids[(CLIENT_ID_SIZE+6)*i]);
        printf("%s :%d",id_toa(&clientids[CLIENT_ID_SIZE*i]),((Messenger*)peers[i])->net->port);
        printf((i%3==2)?"\n---\n":"\n");
    }
    printf("\n");
    
    /* For simplicity sake, one big array */
    uint8_t chatids[CLIENT_ID_SIZE*3];
    
    randombytes_buf((void*)chatids, CLIENT_ID_SIZE*3);
    
    /* NOTE: UNIX only by now */
    FILE *fp=fopen("/dev/urandom","r");
    fread(chatids, sizeof(uint8_t), CLIENT_ID_SIZE*3, fp);
    fclose(fp);
    
    printf("Chats generated:\n");
    for (i=0;i<3;i++)
        printf("%s\n",id_toa(&chatids[CLIENT_ID_SIZE*i]));
    printf("\n");
    
    /* Announcing chat presence */
    printf("Waiting until everybody connects to DHT\n");
    for (;;)
    {
        idle_cylce(peers, 10);
            
        int numconnected=0;
        for (i=0;i<10;i++)
            numconnected+=tox_isconnected(peers[i]);
        if (numconnected==10)
            break;
        usleep(50000);
    }
    
    printf("And 5 more seconds to connect to each other\n");
    idle_n_secs(5, peers, 10);
    
    for (i=0;i<9;i++)
    {
        /* TODO: some of this code might be fit for adaptation in DHT.c */
        DHT *dht=((Messenger*)peers[i])->dht;
        
        Node_format clnode;
        get_closest_known_node(dht, &chatids[CLIENT_ID_SIZE*(i/3)], &clnode);
        
        if (send_gc_announce_request(dht->announce, clnode.ip_port, clnode.client_id, &chatids[CLIENT_ID_SIZE*(i/3)])<0)
        {
            /* TODO: change to check's wrappers when moving into auto_tests */
            printf("Announcing failure");
            goto cleanup;
        }
    }
    
    
    printf("Waiting 10 seconds before sending requests\n");
    idle_n_secs(10, peers, 10);
    
    /* Requesting chat lists */
    for (i=0;i<3;i++)
    {
        /* The last node gets to ask everybody */
        DHT *dht=((Messenger*)peers[9])->dht;
        
        Node_format clnode;
        get_closest_known_node(dht, &chatids[CLIENT_ID_SIZE*i], &clnode);
        
        if (get_gc_announced_nodes_request(dht, clnode.ip_port, clnode.client_id, &chatids[CLIENT_ID_SIZE*i])<0)
        {
            /* TODO: change to check's wrappers when moving into auto_tests */
            printf("Requesting nodes failure");
            goto cleanup;
        }
    }
    
    printf("Waiting 20 seconds\n");
    idle_n_secs(20, peers, 10);
    
    cleanup:
    /* Deinit the nodes */
    for (i=0; i<10; i++)
        tox_kill(peers[i]);
}

int main()
{
    basicannouncetest();
    return 0;
}
