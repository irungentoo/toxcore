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
#define __STDC_FORMAT_MACROS
#include <inttypes.h>

#define PEERCOUNT       4

int certificates_test()
{
    IP localhost;
    DHT *peers[PEERCOUNT];
    Group_Chat *founder;
    Group_Chat *op;
    Group_Chat *user1;
    Group_Chat *user2;
    Group_Credentials * credentials;

    // Initialization
    ip_init(&localhost, 1);
    localhost.ip6.uint8[15]=1;
    
    int i;
    for (i=0; i<PEERCOUNT; i++)
        peers[i]=new_DHT(new_networking(localhost, TOX_PORTRANGE_FROM+i));

    founder = new_groupchat(peers[0]->net);
    op = new_groupchat(peers[1]->net);
    user1 = new_groupchat(peers[2]->net);
    user2 = new_groupchat(peers[3]->net);
    credentials = new_groupcredentials();

    printf("Founder: %s\n", id_toa2(founder->self_public_key, ID_ALL_KEYS));
    printf("Op: %s\n", id_toa2(op->self_public_key, ID_ALL_KEYS));
    printf("User1: %s\n", id_toa2(user1->self_public_key, ID_ALL_KEYS));
    printf("User2: %s\n", id_toa2(user2->self_public_key, ID_ALL_KEYS));

    printf("Chat: %s\n", id_toa2(credentials->chat_public_key, ID_ALL_KEYS));
    printf("-----------------------------------------------------\n");    

    memcpy(founder->chat_public_key, credentials->chat_public_key, EXT_PUBLIC_KEY);
    memcpy(op->chat_public_key, credentials->chat_public_key, EXT_PUBLIC_KEY);
    memcpy(user1->chat_public_key, credentials->chat_public_key, EXT_PUBLIC_KEY);
    memcpy(user2->chat_public_key, credentials->chat_public_key, EXT_PUBLIC_KEY);

    memcpy(founder->founder_public_key, founder->self_public_key, EXT_PUBLIC_KEY);
    memcpy(op->founder_public_key, founder->self_public_key, EXT_PUBLIC_KEY);
    memcpy(user1->founder_public_key, founder->self_public_key, EXT_PUBLIC_KEY);
    memcpy(user2->founder_public_key, founder->self_public_key, EXT_PUBLIC_KEY);

    uint8_t  invite_certificate[PEERCOUNT][INVITE_CERTIFICATE_SIGNED_SIZE];
    uint8_t  common_certificate[PEERCOUNT][COMMON_CERTIFICATE_SIGNED_SIZE];

    // Testing
    int res[PEERCOUNT];
    printf("Making invite certificates for invite request\n");
    res[0] = make_invite_cert(founder->self_secret_key, founder->self_public_key, invite_certificate[0]);
    res[1] = make_invite_cert(op->self_secret_key, op->self_public_key, invite_certificate[1]);
    res[2] = make_invite_cert(user1->self_secret_key, user1->self_public_key, invite_certificate[2]);
    res[3] = make_invite_cert(user2->self_secret_key, user2->self_public_key, invite_certificate[3]);
    for (i=0; i<PEERCOUNT; i++)
        if (res[i]==-1)
            printf("Fail\n");
        else
            printf("Success\n");

    printf("-----------------------------------------------------\n");    
    printf("Signing invite certificates for invite response\n");
    res[0] = sign_certificate(invite_certificate[0], SEMI_INVITE_CERTIFICATE_SIGNED_SIZE, credentials->chat_secret_key, credentials->chat_public_key, invite_certificate[0]);
    res[1] = sign_certificate(invite_certificate[1], SEMI_INVITE_CERTIFICATE_SIGNED_SIZE, founder->self_secret_key, founder->self_public_key, invite_certificate[1]);
    res[2] = sign_certificate(invite_certificate[2], SEMI_INVITE_CERTIFICATE_SIGNED_SIZE, op->self_secret_key, op->self_public_key, invite_certificate[2]);
    res[3] = sign_certificate(invite_certificate[3], SEMI_INVITE_CERTIFICATE_SIGNED_SIZE, op->self_secret_key, op->self_public_key, invite_certificate[3]);
    for (i=0; i<PEERCOUNT; i++)
        if (res[i]==-1)
            printf("Fail\n");
        else
            printf("Success\n");

    memcpy(founder->self_invite_certificate, invite_certificate[0], INVITE_CERTIFICATE_SIGNED_SIZE);
    memcpy(op->self_invite_certificate, invite_certificate[1], INVITE_CERTIFICATE_SIGNED_SIZE);
    memcpy(user1->self_invite_certificate, invite_certificate[2], INVITE_CERTIFICATE_SIGNED_SIZE);
    memcpy(user2->self_invite_certificate, invite_certificate[3], INVITE_CERTIFICATE_SIGNED_SIZE);

    printf("-----------------------------------------------------\n");    
    printf("Verifying invite certificates integrity\n");
    res[0] = verify_cert_integrity(founder->self_invite_certificate);
    res[1] = verify_cert_integrity(op->self_invite_certificate);
    res[2] = verify_cert_integrity(user1->self_invite_certificate);
    res[3] = verify_cert_integrity(user2->self_invite_certificate);
    for (i=0; i<PEERCOUNT; i++)
        if (res[i]==-1)
            printf("Fail\n");
        else
            printf("Success\n");

    printf("-----------------------------------------------------\n");    
    printf("Making common certificate\n");
    res[0] = make_common_cert(op->self_secret_key, op->self_public_key, user1->self_public_key, common_certificate[0], CERT_BAN);
    res[1] = make_common_cert(user1->self_secret_key, user1->self_public_key, user2->self_public_key, common_certificate[1], CERT_BAN);

    for (i=0; i<PEERCOUNT-2; i++)
        if (res[i]==-1)
            printf("Fail\n");
        else
            printf("Success\n");

    printf("-----------------------------------------------------\n");    
    printf("Verifying common certificate integrity\n");
    res[0] = verify_cert_integrity(common_certificate[0]);
    res[1] = verify_cert_integrity(common_certificate[1]);

    for (i=0; i<PEERCOUNT-2; i++)
        if (res[i]==-1)
            printf("Fail\n");
        else
            printf("Success\n");

    // Adding peers to each others peer list
    Group_Peer *peer = calloc(1, sizeof(Group_Peer) * 4);
    memcpy(peer[0].client_id, founder->self_public_key, EXT_PUBLIC_KEY);
    memcpy(peer[0].invite_certificate, founder->self_invite_certificate, INVITE_CERTIFICATE_SIGNED_SIZE);
    peer[0].role = FOUNDER_ROLE;

    memcpy(peer[1].client_id, op->self_public_key, EXT_PUBLIC_KEY);
    memcpy(peer[1].invite_certificate, op->self_invite_certificate, INVITE_CERTIFICATE_SIGNED_SIZE);
    peer[1].role = OP_ROLE;

    memcpy(peer[2].client_id, user1->self_public_key, EXT_PUBLIC_KEY);
    memcpy(peer[2].invite_certificate, user1->self_invite_certificate, INVITE_CERTIFICATE_SIGNED_SIZE);
    peer[2].role = USER_ROLE;

    memcpy(peer[3].client_id, user2->self_public_key, EXT_PUBLIC_KEY);
    memcpy(peer[3].invite_certificate, user2->self_invite_certificate, INVITE_CERTIFICATE_SIGNED_SIZE);
    peer[3].role = USER_ROLE;

    add_peer(founder, &peer[1]);
    add_peer(founder, &peer[2]);
    add_peer(founder, &peer[3]);

    add_peer(op, &peer[0]);
    add_peer(op, &peer[2]);
    add_peer(op, &peer[3]);

    add_peer(user1, &peer[1]);
    add_peer(user1, &peer[0]);
    add_peer(user1, &peer[3]);

    add_peer(user2, &peer[0]);
    add_peer(user2, &peer[1]);
    add_peer(user2, &peer[2]);


    printf("-----------------------------------------------------\n");    
    printf("Processing invite certificates\n");
    printf("User2 peer list before processing:\n");
    printf("Founder verified status: %i\n", user2->group[0].verified);
    printf("Op verified status: %i\n", user2->group[1].verified);
    printf("User1 verified status: %i\n", user2->group[2].verified);
    printf("User2 peer list after processing:\n");
    res[0] = process_invite_cert(user2, user2->group[0].invite_certificate);
    res[1] = process_invite_cert(user2, user2->group[1].invite_certificate);
    res[2] = process_invite_cert(user2, user2->group[2].invite_certificate);

    printf("Founder verified status: %i\n", user2->group[0].verified);
    printf("Op verified status: %i\n", user2->group[1].verified);
    printf("User1 verified status: %i\n", user2->group[2].verified);
  
    printf("-----------------------------------------------------\n");    
    printf("Processing common certificates\n");
    printf("Founder peer list before processing:\n");
    printf("Op ban status: %i\n", founder->group[0].banned);
    printf("User1 ban status: %i\n", founder->group[1].banned);
    printf("User2 ban status: %i\n", founder->group[2].banned);
    printf("Founder peer list after processing:\n");
    res[0] = process_common_cert(founder, common_certificate[0]);
    res[1] = process_common_cert(founder, common_certificate[1]);
    printf("Founder peer list before processing:\n");
    printf("Op ban status: %i\n", founder->group[0].banned);
    printf("User1 ban status: %i\n", founder->group[1].banned);
    printf("User2 ban status: %i\n", founder->group[2].banned);


    printf("-----------------------------------------------------\n");    
    printf("Cert test is finished\n");

    kill_groupchat(founder);
    kill_groupchat(op);
    kill_groupchat(user1);
    kill_groupchat(user2);
    for (i=0; i<PEERCOUNT; i++)
    {
        kill_DHT(peers[i]);
    }

    return 0;
}

void do_gc(DHT *dht)
{
    networking_poll(dht->net);
    do_DHT(dht);
}

int invites_test()
{
    IP localhost;
    DHT *peers[PEERCOUNT];
    Group_Chat *user1;
    Group_Chat *user2;

    // Initialization
    ip_init(&localhost, 1);
    localhost.ip6.uint8[15]=1;
    
    int i;
    for (i=0; i<PEERCOUNT-2; i++)
        peers[i]=new_DHT(new_networking(localhost, TOX_PORTRANGE_FROM+i));

    user1 = new_groupchat(peers[0]->net);
    user2 = new_groupchat(peers[1]->net);

    printf("User1: %s\n", id_toa2(user1->self_public_key, ID_ALL_KEYS));
    printf("User2: %s\n", id_toa2(user2->self_public_key, ID_ALL_KEYS));
    printf("-----------------------------------------------------\n");    
    printf("Sending invite request\n");

    IP_Port on1 = {localhost, user1->net->port};
    IP_Port on2 = {localhost, user2->net->port};

    int res = send_invite_request(user1, on2, user2->self_public_key);
    if (res==-1)
        printf("Fail sending request\n");
    else
        printf("Success sending request\n");

    for (i=0; i<20*1000; i+=50)
    {
        do_gc(peers[0]);
        do_gc(peers[1]);
    }   

    printf("-----------------------------------------------------\n");    
    printf("Verifying certificate integrity:\n");
    res = verify_cert_integrity(user1->self_invite_certificate);
    if (res==-1)
        printf("Fail\n");
    else
        printf("Success\n");

    printf("-----------------------------------------------------\n");    
    printf("Printing certificate details:\n");
    printf("Certificate type: %i\n", user1->self_invite_certificate[0]);
    printf("Inviter pk: %s\n", id_toa2(user1->self_invite_certificate + SEMI_INVITE_CERTIFICATE_SIGNED_SIZE, ID_ALL_KEYS));
    printf("Invitee pk: %s\n", id_toa2(user1->self_invite_certificate + 1, ID_ALL_KEYS));


    kill_groupchat(user1);
    kill_groupchat(user2);
    for (i=0; i<PEERCOUNT-2; i++)
    {
        kill_DHT(peers[i]);
    }

    return 0;

}

int sync_broadcast_test()
{
    IP localhost;
    DHT *peers[PEERCOUNT+1];
    Group_Chat *peers_gc[PEERCOUNT+1];

    // Initialization
    ip_init(&localhost, 1);
    localhost.ip6.uint8[15]=1;
    
    int i;
    int j;
    for (i=0; i<PEERCOUNT+1; i++)
    {
        peers[i]=new_DHT(new_networking(localhost, TOX_PORTRANGE_FROM+i));
        peers_gc[i] = new_groupchat(peers[i]->net);
        printf("Peer Chat %u:\n", i);
        printf("Encryption key:\t%s\n", id_toa2(peers_gc[i]->self_public_key, ID_ENCRYPTION_KEY));
        printf("Signature key:\t%s\n", id_toa2(peers_gc[i]->self_public_key, ID_SIGNATURE_KEY));
    }

    // Testing
    printf("-----------------------------------------------------\n");    
    printf("Sending invite requests to Peer Chat 0:\n");
    IP_Port ipp0 = {localhost, peers_gc[0]->net->port};
    for (i=1; i<PEERCOUNT; i++) {
        int res = send_invite_request(peers_gc[i], ipp0, peers_gc[0]->self_public_key);
        if (res==-1)
            printf("Fail\n");
        else
            printf("Success\n");
    }

    for (i=0; i<20*100000; i+=50)
    {
        for (j=0; j<PEERCOUNT; j++) {
            do_gc(peers[j]);
        }
    }   

    printf("-----------------------------------------------------\n");    
    printf("Verifying certificate integrity:\n");
    for (i=1; i<PEERCOUNT; i++) {
        int res = verify_cert_integrity(peers_gc[i]->self_invite_certificate);
        if (res==-1)
            printf("Fail\n");
        else
            printf("Success\n");
    }

    printf("-----------------------------------------------------\n");    
    printf("Printing Peer Chat 0 peer list:\n");
    for (i=0; i<peers_gc[0]->numpeers; i++) {
        printf("Encryption key:\t%s\n", id_toa2(peers_gc[0]->group[i].client_id, ID_ENCRYPTION_KEY));;
    }
    
    printf("-----------------------------------------------------\n");    
    printf("Printing Peer Chat 1-3 peer list numbers:\n");
    for (i=1; i<PEERCOUNT; i++) {
        printf("Peer Chat: %i\n", peers_gc[i]->numpeers);
    }

    printf("-----------------------------------------------------\n");    
    printf("Sending sync requests:\n");
    unix_time_update(); 
    peers_gc[0]->last_synced_time = unix_time();

    for (i=1; i<PEERCOUNT; i++) {
        int res = send_sync_request(peers_gc[i], ipp0, peers_gc[0]->self_public_key);
        if (res==-1)
            printf("Fail\n");
        else
            printf("Success\n");
    }

    for (i=0; i<20*100000; i+=50)
    {
        for (j=0; j<PEERCOUNT; j++) {
            do_gc(peers[j]);
        }
    }   

    printf("-----------------------------------------------------\n");    
    printf("Printing Peer Chat 1-3 peer list numbers after sync:\n");
    for (i=1; i<PEERCOUNT; i++) {
        printf("Peer Chat: %i\n", peers_gc[i]->numpeers);
    }

    printf("-----------------------------------------------------\n");    
    printf("Printing Peer Chat 1-3 peer lists after sync:\n");
    for (j=1; j<PEERCOUNT; j++) {
        printf("Peer Chat %i:\n", j);
        for (i=0; i<peers_gc[j]->numpeers; i++) {
            printf("Encryption key:\t%s\n", id_toa2(peers_gc[j]->group[i].client_id, ID_ENCRYPTION_KEY));;
        }
    }

    // TODO: make test where we need to update info on some peers, not just add new ones

    printf("-----------------------------------------------------\n");    
    printf("Before ping\n");
    for (i=1; i<PEERCOUNT; i++) {
        int j = peer_in_chat(peers_gc[i], peers_gc[0]->self_public_key);
        printf("Peer Chat %i:\n", i);
        printf("Last received ping from Peer Chat 0 : %" PRIu64 "\n", peers_gc[i]->group[j].last_rcvd_ping);
    }


    for (i=0; i<5*1000; i+=50) {
        do_groupchat(peers_gc[0]);
        usleep(50000); /* usecs */
    }

    for (i=0; i<20*100000; i+=50)
    {
        for (j=0; j<PEERCOUNT; j++) {
            do_gc(peers[j]);
        }
    }   

    printf("After ping\n");
    for (i=1; i<PEERCOUNT; i++) {
        int j = peer_in_chat(peers_gc[i], peers_gc[0]->self_public_key);
        printf("Peer Chat %i:\n", i);
        printf("Last received ping from Peer Chat 0 : %" PRIu64 "\n", peers_gc[i]->group[j].last_rcvd_ping);
    }

    printf("-----------------------------------------------------\n");    
    printf("Peer Chat 1 sending away status to Peer Chat 0\n");

    send_status(peers_gc[1], ipp0, peers_gc[0]->self_public_key, AWAY_STATUS);
    int num = peer_in_chat(peers_gc[0], peers_gc[1]->self_public_key);

    for (i=0; i<20*100000; i+=50)
    {
        for (j=0; j<PEERCOUNT; j++) {
            do_gc(peers[j]);
        }
    }   

    if (peers_gc[0]->group[num].status==AWAY_STATUS) {
        printf("Status is away\n");
    } else
        printf("Fail\n");

    printf("-----------------------------------------------------\n");    
    printf("Peer Chat 1 sending new nick to Peer Chat 0\n");
    char nick[] = "Vasya";
    strncpy(peers_gc[1]->self_nick, nick, 5);
    peers_gc[1]->self_nick_len = 5;
    send_change_nick(peers_gc[1], ipp0, peers_gc[0]->self_public_key);
    for (i=0; i<20*100000; i+=50)
    {
        for (j=0; j<PEERCOUNT; j++) {
            do_gc(peers[j]);
        }
    }  
    peers_gc[0]->group[num].nick[peers_gc[0]->group[num].nick_len]=0; 
    printf("%s\n", peers_gc[0]->group[num].nick);

    printf("-----------------------------------------------------\n");    
    printf("Peer Chat 1 sending new topic to Peer Chat 0\n");
    char topic[] = "Skype is trash";
    strncpy(peers_gc[1]->topic, topic, 14);
    peers_gc[1]->topic_len = 14;
    send_change_topic(peers_gc[1], ipp0, peers_gc[0]->self_public_key);
    for (i=0; i<20*100000; i+=50)
    {
        for (j=0; j<PEERCOUNT; j++) {
            do_gc(peers[j]);
        }
    }  
    peers_gc[0]->topic[peers_gc[0]->topic_len]=0; 
    printf("%s\n", peers_gc[0]->topic);

    printf("-----------------------------------------------------\n");    
    printf("Peer Chat 4 sending himself to Peer Chat 0 after being invite by Peer Chat 1\n");

    IP_Port ipp1 = {localhost, peers_gc[1]->net->port};
    int res = send_invite_request(peers_gc[4], ipp1, peers_gc[1]->self_public_key);
    for (i=0; i<20*100000; i+=50)
    {
        for (j=0; j<PEERCOUNT+1; j++) {
            do_gc(peers[j]);
        }
    }  
    send_new_peer(peers_gc[4], ipp0, peers_gc[0]->self_public_key);
    
    for (i=0; i<20*100000; i+=50)
    {
        for (j=0; j<PEERCOUNT+1; j++) {
            do_gc(peers[j]);
        }
    }  

    num = peer_in_chat(peers_gc[0], peers_gc[4]->self_public_key);

    printf("Peer Chat 4 number in Peer Chat 0 peer list: %i\n", num);

    // Finalization
    for (i=0; i<PEERCOUNT; i++)
    {
        kill_groupchat(peers_gc[i]);
        kill_DHT(peers[i]);
    }

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
    //certificates_test();
    //invites_test();
    sync_broadcast_test();
    //basic_group_chat_test();
}