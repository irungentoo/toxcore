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

    struct Tox_Options *opts = tox_options_new(nullptr);
    tox_options_set_udp_enabled(opts, false);
    Tox *tox_tcp = tox_new_log(opts, nullptr, nullptr);
    tox_options_free(opts);

    tox_bootstrap(tox_tcp, "163.172.136.118", 33445, key, nullptr);
    tox_add_tcp_relay(tox_tcp, "163.172.136.118", 33445, key, nullptr);

    printf("Waiting for connection");

    do {
        printf(".");
        fflush(stdout);

        tox_iterate(tox_tcp, nullptr);
        c_sleep(ITERATION_INTERVAL);
    } while (tox_self_get_connection_status(tox_tcp) == TOX_CONNECTION_NONE);

    const Tox_Connection status = tox_self_get_connection_status(tox_tcp);
    ck_assert_msg(status == TOX_CONNECTION_TCP,
                  "expected TCP connection, but got %d", status);
    printf("Connection (TCP): %d\n", status);

    tox_kill(tox_tcp);
    return 0;
}
