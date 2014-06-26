/* Basic group announcing testing
 * TODO: please add license and everything */

#include "../toxcore/tox.h"
#include "../toxcore/network.h"
#include "../toxcore/DHT.h"
#include "../toxcore/ping.h"
#include "../toxcore/group_announce.h"
#include "../toxcore/Messenger.h"

#include <stdio.h>
#include <stdlib.h>

/* TODO: maybe something like this already exists */
void print_as_id(uint8_t *startptr)
{
    int i;
    for (i=0;i<CLIENT_ID_SIZE;i++)
        printf("%02x",startptr[i]);
}

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

/* TODO: this looks ugly by now */
void basicannouncetest()
{
    /* The design is the following:
     * we have 10 tox instances, they form 3 chats of 3 members
     * the 10ths then proceeds to query the list of chat's participants */
    Tox *peers[10];
    int i;
    
    /* Init the nodes */
    printf("Nodes generated:\n");
    uint8_t clientids[(CLIENT_ID_SIZE+6)*10];
    for (i=0; i<10; i++)
    {
        peers[i]=tox_new(TOX_ENABLE_IPV6_DEFAULT);
        tox_get_address(peers[i],&clientids[(CLIENT_ID_SIZE+6)*i]);
        print_as_id(&clientids[CLIENT_ID_SIZE*i]);
        printf((i%3==2)?"\n---\n":"\n");
    }
    printf("\n");
    
    /* For simplicity sake, one big array */
    uint8_t chatids[CLIENT_ID_SIZE*3];
    
    /* NOTE: UNIX only by now */
    FILE *fp=fopen("/dev/urandom","r");
    fread(chatids, sizeof(uint8_t), CLIENT_ID_SIZE*3, fp);
    fclose(fp);
    
    printf("Chats generated:\n");
    for (i=0;i<3;i++)
    {
        print_as_id(&chatids[CLIENT_ID_SIZE*i]);
        printf("\n");
    }
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
    
    for (i=0;i<9;i++)
    {
        // group_announce(clientids[(CLIENT_ID_SIZE+6)*i], chatids[CLIENT_ID_SIZE*(i/3)]);
    }
    
    
    printf("Waiting 10 seconds before sending requests\n");
    idle_n_secs(10, peers, 10);
    
    /* Requesting chat lists */
    for (i=0;i<9;i++)
    {
        // group_get_nodes(chatids[(CLIENT_ID_SIZE*(i/3)]);
    }
    
    /* Deinit the nodes */
    for (i=0; i<10; i++)
        tox_kill(peers[i]);
}

int main()
{
    basicannouncetest();
    return 0;
}
