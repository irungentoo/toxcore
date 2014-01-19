#include "../../toxcore/group_chats.h"
#define NUM_CHATS 8

#if defined(_WIN32) || defined(__WIN32__) || defined (WIN32)
#define c_sleep(x) Sleep(1*x)
#else
#define c_sleep(x) usleep(1000*x)
#endif
Group_Chat *chat;

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

unsigned char *hex_string_to_bin(char hex_string[])
{
    size_t len = strlen(hex_string);
    unsigned char *val = malloc(len);
    char *pos = hex_string;
    int i;

    for (i = 0; i < len; ++i, pos += 2)
        sscanf(pos, "%2hhx", &val[i]);

    return val;
}

void print_message(Group_Chat *chat, int peer_number, uint8_t *message, uint16_t length, void *userdata)
{
    printf("%u: %s | %u\n", peer_number, message, length);
}

int main(int argc, char *argv[])
{
    IP ip;
    ip.uint32 = 0;
    uint32_t i;

    chat = new_groupchat(new_networking(ip, 12745));

    if (chat == 0)
        exit(1);

    networking_registerhandler(chat->net, 48, &handle_groupchatpacket, chat);

    callback_groupmessage(chat, &print_message, 0);

    printf("ok\n");
    IP_Port bootstrap_ip_port;
    bootstrap_ip_port.port = htons(atoi(argv[2]));
    /* bootstrap_ip_port.ip.c[0] = 127;
     * bootstrap_ip_port.ip.c[1] = 0;
     * bootstrap_ip_port.ip.c[2] = 0;
     * bootstrap_ip_port.ip.c[3] = 1; */
    bootstrap_ip_port.ip.uint32 = inet_addr(argv[1]);

    chat_bootstrap(chat, bootstrap_ip_port, hex_string_to_bin(argv[3]));

    while (1) {

        networking_poll(chat->net);
        do_groupchat(chat);
        printf("%u ", chat->numpeers);
        printf("%u\n", group_sendmessage(chat, "Install Gentoo", sizeof("Install Gentoo")));
        //print_close(chat->close);
        // print_group(chat);

        c_sleep(100);
    }

    return 0;
}
