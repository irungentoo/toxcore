#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <stdio.h>

#include "../testing/misc_tools.h"
#include "check_compat.h"

static uint8_t const key[] = {
    0x2C, 0x28, 0x9F, 0x9F, 0x37, 0xC2, 0x0D, 0x09,
    0xDA, 0x83, 0x56, 0x55, 0x88, 0xBF, 0x49, 0x6F,
    0xAB, 0x37, 0x64, 0x85, 0x3F, 0xA3, 0x81, 0x41,
    0x81, 0x7A, 0x72, 0xE3, 0xF1, 0x8A, 0xCA, 0x0B,
};

int main(void)
{
    setvbuf(stdout, nullptr, _IONBF, 0);

    Tox *tox_udp = tox_new_log(nullptr, nullptr, nullptr);

    tox_bootstrap(tox_udp, "163.172.136.118", 33445, key, nullptr);

    printf("Waiting for connection");

    do {
        printf(".");
        fflush(stdout);

        tox_iterate(tox_udp, nullptr);
        c_sleep(ITERATION_INTERVAL);
    } while (tox_self_get_connection_status(tox_udp) == TOX_CONNECTION_NONE);

    const Tox_Connection status = tox_self_get_connection_status(tox_udp);
    ck_assert_msg(status == TOX_CONNECTION_UDP,
                  "expected connection status to be UDP, but got %d", status);
    printf("Connection (UDP): %d\n", tox_self_get_connection_status(tox_udp));

    tox_kill(tox_udp);
    return 0;
}
