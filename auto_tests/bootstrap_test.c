#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <stdio.h>

#include "../testing/misc_tools.h"
#include "check_compat.h"

static uint8_t const key[] = {
    0x15, 0xE9, 0xC3, 0x09, 0xCF, 0xCB, 0x79, 0xFD,
    0xDF, 0x0E, 0xBA, 0x05, 0x7D, 0xAB, 0xB4, 0x9F,
    0xE1, 0x5F, 0x38, 0x03, 0xB1, 0xBF, 0xF0, 0x65,
    0x36, 0xAE, 0x2E, 0x5B, 0xA5, 0xE4, 0x69, 0x0E,
};

int main(void)
{
    setvbuf(stdout, nullptr, _IONBF, 0);

    Tox *tox_udp = tox_new_log(nullptr, nullptr, nullptr);

    tox_bootstrap(tox_udp, "tox.ngc.zone", 33445, key, nullptr);

    printf("Waiting for connection");

    while (tox_self_get_connection_status(tox_udp) == TOX_CONNECTION_NONE) {
        printf(".");
        fflush(stdout);

        tox_iterate(tox_udp, nullptr);
        c_sleep(ITERATION_INTERVAL);
    }

    const TOX_CONNECTION status = tox_self_get_connection_status(tox_udp);
    ck_assert_msg(status == TOX_CONNECTION_UDP,
                  "expected connection status to be UDP, but got %d", status);
    printf("Connection (UDP): %d\n", tox_self_get_connection_status(tox_udp));

    tox_kill(tox_udp);
    return 0;
}
