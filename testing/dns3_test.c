

#include "../toxdns/toxdns.h"
#include "../toxcore/tox.h"
#include "misc_tools.c"


int main(int argc, char *argv[])
{
    if (argc < 4) {
        printf("Usage: %s domain domain_public_key queried_username\nEX: %s utox.org D3154F65D28A5B41A05D4AC7E4B39C6B1C233CC857FB365C56E8392737462A12 username\n",
               argv[0], argv[0]);
        exit(0);
    }

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
    printf("Do a DNS request and find the TXT record for:\n%s\nThen paste the contents of the data contained in the id field here:\n",
           string);

    scanf("%s", string);
    uint8_t tox_id[TOX_FRIEND_ADDRESS_SIZE];

    if (tox_decrypt_dns3_TXT(d, tox_id, string, strlen((char *)string), request_id) != 0)
        return -1;

    printf("The Tox id for username %s is:\n", argv[3]);

    //unsigned int i;
    for (i = 0; i < TOX_FRIEND_ADDRESS_SIZE; ++i) {
        printf("%02hhX", tox_id[i]);
    }

    printf("\n");
    return 0;
}
