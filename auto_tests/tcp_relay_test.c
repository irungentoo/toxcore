#include <stdio.h>

#include "../testing/misc_tools.h"
#include "check_compat.h"

#include "auto_test_support.h"

int main(void)
{
    setvbuf(stdout, nullptr, _IONBF, 0);

    struct Tox_Options *opts = tox_options_new(nullptr);
    tox_options_set_udp_enabled(opts, false);
    Tox *tox_tcp = tox_new_log(opts, nullptr, nullptr);
    tox_options_free(opts);

    bootstrap_tox_live_network(tox_tcp, true);

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
