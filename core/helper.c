#include "helper.h"

static int seed = -1; /* Not initiated */

int set_ip_port(const char *ip, short port, IP_Port *dest)
{
    if (!dest) {
        return -1;
    }

    dest->ip.i = resolve_addr(ip);
    dest->port = htons(port);

    return 0;
}

uint32_t get_random_number(uint32_t max)
{
    if (seed < 0) {
        srand(time(NULL));
        seed++;
    }

    if (max <= 0)
        return rand();
    else
        return rand() % max;
}

void memadd(uint8_t *dest, uint16_t from, const uint8_t *source, uint16_t size)
{
    uint16_t i;
    for (i = 0; from < size; ++ from) {
        dest[from] = source[i];
        ++ i;
    }
}
