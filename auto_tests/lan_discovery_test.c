#ifndef _XOPEN_SOURCE
#define _XOPEN_SOURCE 600
#endif

#include "helpers.h"

int main(void)
{
    setvbuf(stdout, nullptr, _IONBF, 0);
    Tox *tox1 = tox_new_log_lan(nullptr, nullptr, nullptr, /* lan_discovery */true);
    Tox *tox2 = tox_new_log_lan(nullptr, nullptr, nullptr, /* lan_discovery */true);

    printf("Waiting for LAN discovery");

    while (tox_self_get_connection_status(tox1) == TOX_CONNECTION_NONE ||
            tox_self_get_connection_status(tox2) == TOX_CONNECTION_NONE) {
        printf(".");
        fflush(stdout);

        tox_iterate(tox1, nullptr);
        tox_iterate(tox2, nullptr);
        c_sleep(1000);
    }

    printf(" %d <-> %d\n",
           tox_self_get_connection_status(tox1),
           tox_self_get_connection_status(tox2));

    tox_kill(tox2);
    tox_kill(tox1);
    return 0;
}
