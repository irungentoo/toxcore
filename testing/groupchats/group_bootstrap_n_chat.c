/* Basic group chats testing
 */

#include "../../toxcore/DHT.h"
#include "../../toxcore/tox.h"
#include "../../toxcore/network.h"
#include "../../toxcore/ping.h"
#include "../../toxcore/util.h"
#include "../../toxcore/Messenger.h"

#include <stdio.h>
#include <stdlib.h>

#define PEERCOUNT       20
#define min(a,b) ((a)>(b)?(b):(a))

void on_group_peer_join(Messenger *m, int groupnumber, uint32_t peernumber, void *userdata)
{
    GC_Chat *ct = gc_get_group(m->group_handler, groupnumber);
    printf("Number of peers in the chat: %d\n", gc_get_numpeers(ct));    
}

int main(int argc, char *argv[])
{
    /* Set ip to IPv6 loopback. TODO: IPv4 fallback? */
    IP localhost;
    ip_init(&localhost, 1);
    localhost.ip6.uint8[15]=1;
    Messenger_Options options = {0};
    options.ipv6enabled = TOX_ENABLE_IPV6_DEFAULT;    

    Messenger* tox[PEERCOUNT];
    Messenger* chat;
    chat = new_messenger(&options);

    int i;
    for (i=0; i<PEERCOUNT; i++)
    {
        tox[i] = new_messenger(&options);
    }

    printf("%s\n", id_toa(tox[0]->dht->self_public_key));
    IP_Port ip_port;
    ip_copy(&ip_port.ip, &localhost);
    ip_port.port = tox[0]->dht->net->port;
    printf("%s\n", ip_ntoa(&ip_port.ip));
    printf("%d\n", ip_port.port);

    printf("Bootstrapping from node\n");

    for (i=1; i<PEERCOUNT; i++)
    {
        DHT_bootstrap(tox[0]->dht, ip_port, tox[0]->dht->self_public_key);
    }

    DHT_bootstrap(chat->dht, ip_port, tox[0]->dht->self_public_key);

    printf("Waiting until every Tox is connected\n");
    for (;;)
    {
        for (i=0; i<PEERCOUNT; i++) {
            do_messenger(tox[i]);
        }
        do_messenger(chat);
        
        int numconnected=0;
        for (i=0;i<PEERCOUNT;i++) 
            numconnected+=DHT_isconnected(tox[i]->dht);
        //printf("%d\n", numconnected);

        if (numconnected>PEERCOUNT*min(PEERCOUNT-1,LCLIENT_LIST))
            break;

        /* TODO: busy wait might be slightly more efficient here */
        usleep(50000);
    }

    printf("Network is connected\n");    

    chat->group_handler = new_groupchats(chat);
    int groupnumber = gc_group_add(chat->group_handler, "Test", 4);
    if (groupnumber<0)
        printf("Cannot create group\n");    

    GC_Chat *ct = gc_get_group(chat->group_handler, groupnumber);
    printf("%s%s\n", id_toa(ENC_KEY(ct->chat_public_key)), id_toa(SIG_KEY(ct->chat_public_key)));

    gc_callback_peer_join(chat, on_group_peer_join, NULL);

    while (true) {
        for (i=0; i<PEERCOUNT; i++) {
            do_messenger(tox[i]);
        }
        do_messenger(chat);
      	usleep(50000); /* usecs */
    }
}