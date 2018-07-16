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

    struct Tox_Options *opts = tox_options_new(nullptr);
    tox_options_set_udp_enabled(opts, false);
    Tox *tox_tcp = tox_new_log(opts, nullptr, nullptr);
    tox_options_free(opts);

    tox_bootstrap(tox_tcp, "tox.ngc.zone", 33445, key, nullptr);
    tox_add_tcp_relay(tox_tcp, "tox.ngc.zone", 33445, key, nullptr);

    printf("Waiting for connection");

    while (tox_self_get_connection_status(tox_tcp) == TOX_CONNECTION_NONE) {
        printf(".");
        fflush(stdout);

        tox_iterate(tox_tcp, nullptr);
        c_sleep(ITERATION_INTERVAL);
    }

    const TOX_CONNECTION status = tox_self_get_connection_status(tox_tcp);
    ck_assert_msg(status == TOX_CONNECTION_TCP,
                  "expected TCP connection, but got %d", status);
    printf("Connection (TCP): %d\n", status);

    tox_kill(tox_tcp);
    return 0;
}
