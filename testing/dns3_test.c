

#include "../toxdns/toxdns.h"
#include "../toxcore/tox.h"
#include "../toxcore/network.h"
#include "misc_tools.c"

#if defined(_WIN32) || defined(__WIN32__) || defined (WIN32)

#define c_sleep(x) Sleep(1*x)

#else
#define c_sleep(x) usleep(1000*x)

#endif

uint32_t create_packet(uint8_t *packet, uint8_t *string, uint8_t str_len, uint8_t id)
{
    memset(packet, 0, str_len + 13 + 16);
    packet[0] = id;
    packet[1] = rand();
    packet[5] = 1;
    packet[11] = 1;
    packet[12] = '.';
    memcpy(packet + 13, string, str_len);
    uint32_t i, c = 0;

    for (i = str_len + 12; i != 11; --i) {
        if (packet[i] == '.') {
            packet[i] = c;
            c = 0;
        } else {
            ++c;
        }
    }

    packet[str_len + 13 + 2] = 16;
    packet[str_len + 13 + 4] = 1;
    packet[str_len + 13 + 7] = 0x29;
    packet[str_len + 13 + 8] = 16;
    packet[str_len + 13 + 12] = 0x80;
    return str_len + 13 + 16;
}

int main(int argc, char *argv[])
{
    if (argc < 4) {
        printf("Usage: %s domain domain_public_key queried_username\nEX: %s utox.org D3154F65D28A5B41A05D4AC7E4B39C6B1C233CC857FB365C56E8392737462A12 username\n",
               argv[0], argv[0]);
        exit(0);
    }

    IP ip = {0};
    ip.family = AF_INET;
    sock_t sock = socket(ip.family, SOCK_DGRAM, IPPROTO_UDP);

    if (!sock_valid(sock))
        return -1;

    if (!addr_resolve_or_parse_ip(argv[1], &ip, 0))
        return -1;

    struct sockaddr_in target;
    size_t addrsize = sizeof(struct sockaddr_in);
    target.sin_family = AF_INET;
    target.sin_addr = ip.ip4.in_addr;
    target.sin_port = htons(53);

    uint8_t string[1024] = {0};
    void *d = tox_dns3_new(hex_string_to_bin(argv[2]));
    unsigned int i;
    uint32_t request_id;
    /*
    for (i = 0; i < 255; ++i) {
        tox_generate_dns3_string(d, string, sizeof(string), &request_id, string, i);
        printf("%s\n", string);
    }*/
    int len = tox_generate_dns3_string(d, string + 1, sizeof(string) - 1, &request_id, (uint8_t *)argv[3], strlen(argv[3]));

    if (len == -1)
        return -1;

    string[0] = '_';
    memcpy(string + len + 1, "._tox.", sizeof("._tox."));
    memcpy((char *)(string + len + 1 + sizeof("._tox.") - 1), argv[1], strlen(argv[1]));
    uint8_t packet[512];
    uint8_t id = rand();
    uint32_t p_len = create_packet(packet, string, strlen((char *)string), id);

    if (sendto(sock, (char *) packet, p_len, 0, (struct sockaddr *)&target, addrsize) != p_len)
        return -1;

    uint8_t buffer[512] = {};
    int r_len = recv(sock, buffer, sizeof(buffer), 0);

    if (r_len < (int)p_len)
        return -1;

    for (i = r_len - 1; i != 0 && buffer[i] != '='; --i);

    uint8_t tox_id[TOX_FRIEND_ADDRESS_SIZE];

    if (tox_decrypt_dns3_TXT(d, tox_id, buffer + i + 1, r_len - (i + 1), request_id) != 0)
        return -1;

    printf("The Tox id for username %s is:\n", argv[3]);

    //unsigned int i;
    for (i = 0; i < TOX_FRIEND_ADDRESS_SIZE; ++i) {
        printf("%02hhX", tox_id[i]);
    }

    printf("\n");
    return 0;
}
