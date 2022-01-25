#include <stdio.h>

#include "../testing/misc_tools.h"
#include "check_compat.h"

#include "auto_test_support.h"

int main(void)
{
    setvbuf(stdout, nullptr, _IONBF, 0);

    Tox *tox_udp = tox_new_log(nullptr, nullptr, nullptr);

    bootstrap_tox_live_network(tox_udp, false);

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
