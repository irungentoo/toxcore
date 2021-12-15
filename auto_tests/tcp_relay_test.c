#include <stdio.h>

#include "../testing/misc_tools.h"
#include "check_compat.h"

static uint8_t const key1[] = {
    0x02, 0x80, 0x7C, 0xF4, 0xF8, 0xBB, 0x8F, 0xB3,
    0x90, 0xCC, 0x37, 0x94, 0xBD, 0xF1, 0xE8, 0x44,
    0x9E, 0x9A, 0x83, 0x92, 0xC5, 0xD3, 0xF2, 0x20,
    0x00, 0x19, 0xDA, 0x9F, 0x1E, 0x81, 0x2E, 0x46,
};

static uint8_t const key2[] = {
    0x3F, 0x0A, 0x45, 0xA2, 0x68, 0x36, 0x7C, 0x1B,
    0xEA, 0x65, 0x2F, 0x25, 0x8C, 0x85, 0xF4, 0xA6,
    0x6D, 0xA7, 0x6B, 0xCA, 0xA6, 0x67, 0xA4, 0x9E,
    0x77, 0x0B, 0xCC, 0x49, 0x17, 0xAB, 0x6A, 0x25,
};

int main(void)
{
    setvbuf(stdout, nullptr, _IONBF, 0);

    struct Tox_Options *opts = tox_options_new(nullptr);
    tox_options_set_udp_enabled(opts, false);
    Tox *tox_tcp = tox_new_log(opts, nullptr, nullptr);
    tox_options_free(opts);

    tox_bootstrap(tox_tcp, "78.46.73.141", 33445, key1, nullptr);
    tox_bootstrap(tox_tcp, "tox.initramfs.io", 33445, key2, nullptr);

    Tox_Err_Bootstrap tcp_err;
    tox_add_tcp_relay(tox_tcp, "78.46.73.141", 33445, key1, &tcp_err);
    ck_assert_msg(tcp_err == TOX_ERR_BOOTSTRAP_OK,
                  "attempting to add tcp relay returned with an error: %d",
                  tcp_err);
    tox_add_tcp_relay(tox_tcp, "tox.initramfs.io", 33445, key2, &tcp_err);
    ck_assert_msg(tcp_err == TOX_ERR_BOOTSTRAP_OK,
                  "attempting to add tcp relay returned with an error: %d",
                  tcp_err);

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
