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

int certificates_test()
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
    }

    uint8_t  invite_certificate[INVITE_CERTIFICATE_SIGNED_SIZE];
    uint8_t  common_certificate[COMMON_CERTIFICATE_SIGNED_SIZE];

    int res = make_invite_cert(peers_gc[0]->self_secret_key, peers_gc[0]->self_public_key, invite_certificate);
    if (res==-1)
        printf("Make invite cert failed!\n");

    res = sign_certificate(invite_certificate, SEMI_INVITE_CERTIFICATE_SIGNED_SIZE, peers_gc[1]->self_secret_key, peers_gc[1]->self_public_key, invite_certificate);
    if (res==-1)
        printf("Sign invite cert failed!\n");

    //res = verify_cert_integrity(invite_certificate); - core dumped!!!
/*    if (res==-1)
        printf("Invite cert is corrupted!\n");

*/
    printf("Cert test is finished\n");
    return 0;
}

int basic_group_chat_test()
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
        printf("Encryption key:\t%s\n", id_toa2(peers_gc[i]->self_public_key, ID_ENCRYPTION_KEY));
        printf("Signature key:\t%s\n", id_toa2(peers_gc[i]->self_public_key, ID_SIGNATURE_KEY));
    }


    Group_Credentials *credentials = new_groupcredentials();
    printf("Chat Credentials:\n");
    printf("Encryption key:\t%s\n", id_toa2(credentials->chat_public_key, ID_ENCRYPTION_KEY));
    printf("Signature key:\t%s\n", id_toa2(credentials->chat_public_key, ID_SIGNATURE_KEY));

    // Finalization
    for (i=0; i<PEERCOUNT; i++)
    {
        kill_groupchat(peers_gc[i]);
        kill_DHT(peers[i]);
    }

    return 0;
}

int main()
{
    certificates_test();
    //basic_group_chat_test();
}