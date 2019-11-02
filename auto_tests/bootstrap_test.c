#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <stdio.h>

#include "../testing/misc_tools.h"
#include "check_compat.h"

static uint8_t const key[] = {
    0x02, 0x80, 0x7C, 0xF4, 0xF8, 0xBB, 0x8F, 0xB3,
    0x90, 0xCC, 0x37, 0x94, 0xBD, 0xF1, 0xE8, 0x44,
    0x9E, 0x9A, 0x83, 0x92, 0xC5, 0xD3, 0xF2, 0x20,
    0x00, 0x19, 0xDA, 0x9F, 0x1E, 0x81, 0x2E, 0x46,
};

int main(void)
{
    setvbuf(stdout, nullptr, _IONBF, 0);

    Tox *tox_udp = tox_new_log(nullptr, nullptr, nullptr);

    tox_bootstrap(tox_udp, "78.46.73.141", 33445, key, nullptr);

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
