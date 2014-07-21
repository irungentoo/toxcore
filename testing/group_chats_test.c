/* Basic group chats testing
 */

#include "../toxcore/tox.h"
#include "../toxcore/network.h"
#include "../toxcore/DHT.h"
#include "../toxcore/ping.h"
#include "../toxcore/util.h"
#include "../toxcore/group_chats_new.h"

#include <stdio.h>
#include <stdlib.h>

#define PEERCOUNT       1

int main()
{
    IP localhost;
    DHT *peers[PEERCOUNT];
    Group_Chat *peers_gc[PEERCOUNT];

    ip_init(&localhost, 1);
    localhost.ip6.uint8[15]=1;
    
    int i;
    for (i=0; i<PEERCOUNT; i++)
    {
        peers[i]=new_DHT(new_networking(localhost, TOX_PORTRANGE_FROM+i));
        peers_gc[i] = new_groupchat(peers[i]->net);
    }

    return 0;
}