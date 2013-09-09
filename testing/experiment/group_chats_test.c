#include "../../toxcore/group_chats.h"
#define NUM_CHATS 8

#ifdef WIN32
#define c_sleep(x) Sleep(1*x)
#else
#define c_sleep(x) usleep(1000*x)
#endif
Group_Chat *chats[NUM_CHATS];

void print_close(Group_Close *close)
{
    uint32_t i, j;
    IP_Port p_ip;
    printf("___________________CLOSE________________________________\n");

    for (i = 0; i < GROUP_CLOSE_CONNECTIONS; i++) {
        printf("ClientID: ");

        for (j = 0; j < CLIENT_ID_SIZE; j++) {
            printf("%02hhX", close[i].client_id[j]);
        }

        p_ip = close[i].ip_port;
        printf("\nIP: %u.%u.%u.%u Port: %u", p_ip.ip.uint8[0], p_ip.ip.uint8[1], p_ip.ip.uint8[2], p_ip.ip.uint8[3],
               ntohs(p_ip.port));
        printf("\nTimestamp: %llu", (long long unsigned int) close[i].last_recv);
        printf("\n");
    }
}

void print_group(Group_Chat *chat)
{
    uint32_t i, j;
    printf("-----------------\nClientID: ");

    for (j = 0; j < CLIENT_ID_SIZE; j++) {
        printf("%02hhX", chat->self_public_key[j]);
    }

    printf("\n___________________GROUP________________________________\n");

    for (i = 0; i < chat->numpeers; i++) {
        printf("ClientID: ");

        for (j = 0; j < CLIENT_ID_SIZE; j++) {
            printf("%02hhX", chat->group[i].client_id[j]);
        }

        printf("\nTimestamp: %llu", (long long unsigned int) chat->group[i].last_recv);
        printf("\nlast_pinged: %llu", (long long unsigned int) chat->group[i].last_pinged);
        printf("\npingid: %llu", (long long unsigned int) chat->group[i].pingid);
        printf("\n");
    }
}

void print_message(Group_Chat *chat, int peer_number, uint8_t *message, uint16_t length, void *userdata)
{
    printf("%u: %s | %u\n", peer_number, message, length);
}

int main()
{
    IP ip;
    ip.uint32 = 0;
    uint32_t i;


    for (i = 0; i < NUM_CHATS; ++i) {
        chats[i] = new_groupchat(new_networking(ip, 12745));

        if (chats[i] == 0)
            exit(1);

        networking_registerhandler(chats[i]->net, 48, &handle_groupchatpacket, chats[i]);
        callback_groupmessage(chats[i], &print_message, 0);
    }

    printf("ok\n");
    IP_Port ip_port;
    ip_port.ip.uint32 = 0;
    ip_port.ip.uint8[0] = 127;
    ip_port.ip.uint8[3] = 1;
    ip_port.port = htons(12745);

    for (i = 0; i < NUM_CHATS; ++i) {
        group_newpeer(chats[0], chats[i]->self_public_key);
        chat_bootstrap(chats[i], ip_port, chats[0]->self_public_key);
        printf("%u\n", i);
    }

    while (1) {
        for (i = 0; i < NUM_CHATS; ++i) {
            networking_poll(chats[i]->net);
            do_groupchat(chats[i]);
            printf("%u\n", chats[i]->numpeers);
            print_close(chats[i]->close);
            print_group(chats[i]);
        }

        c_sleep(100);
    }

    return 0;
}
