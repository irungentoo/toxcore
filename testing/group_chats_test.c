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

#define PEERCOUNT       2

int main()
{
    IP localhost;
    DHT *peers[PEERCOUNT];
    Group_Chat *peers_gc[PEERCOUNT];

    // Initialization
    ip_init(&localhost, 1);
    localhost.ip6.uint8[15]=1;
    
    int i;
    for (i=0; i<PEERCOUNT; i++)
    {
        peers[i]=new_DHT(new_networking(localhost, TOX_PORTRANGE_FROM+i));
        peers_gc[i] = new_groupchat(peers[i]->net);
        printf("Peer Chat %u:\n", i);
        printf("Encryption key: %s\n", id_toa2(peers_gc[i]->self_public_key, ID_ENCRYPTION_KEY));
        printf("Signature key: %s\n", id_toa2(peers_gc[i]->self_public_key, ID_SIGNATURE_KEY));
    }


    Group_Credentials *credentials = new_groupcredentials();
    printf("Chat Credentials:\n");
    printf("Encryption key: %s\n", id_toa2(credentials->chat_public_key, ID_ENCRYPTION_KEY));
    printf("Signature key: %s\n", id_toa2(credentials->chat_public_key, ID_SIGNATURE_KEY));

    // Finalization
    for (i=0; i<PEERCOUNT; i++)
    {
    	kill_groupchat(peers_gc[i]);
    	kill_DHT(peers[i]);
    }

    return 0;
}