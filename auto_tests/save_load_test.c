/* Tests that we can save and load Tox data.
 */

#ifndef _XOPEN_SOURCE
#define _XOPEN_SOURCE 600
#endif

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "check_compat.h"

#include <stdio.h>
#include <stdlib.h>
#include <time.h>

#include "../toxcore/ccompat.h"
#include "../toxcore/tox.h"
#include "../toxcore/util.h"

#include "helpers.h"

static void accept_friend_request(Tox *m, const uint8_t *public_key, const uint8_t *data, size_t length, void *userdata)
{
    if (length == 7 && memcmp("Gentoo", data, 7) == 0) {
        tox_friend_add_norequest(m, public_key, nullptr);
    }
}

static unsigned int connected_t1;
static void tox_connection_status(Tox *tox, TOX_CONNECTION connection_status, void *user_data)
{
    if (connected_t1 && !connection_status) {
        ck_abort_msg("Tox went offline");
    }

    ck_assert_msg(connection_status == TOX_CONNECTION_UDP, "wrong status %u", connection_status);

    connected_t1 = connection_status;
}

static void test_few_clients(void)
{
    uint32_t index[] = { 1, 2, 3 };
    time_t con_time = 0, cur_time = time(nullptr);
    Tox *tox1 = tox_new_log(nullptr, nullptr, &index[0]);
    Tox *tox2 = tox_new_log(nullptr, nullptr, &index[1]);
    Tox *tox3 = tox_new_log(nullptr, nullptr, &index[2]);

    ck_assert_msg(tox1 && tox2 && tox3, "Failed to create 3 tox instances");

    printf("bootstrapping tox2 and tox3 off tox1\n");
    uint8_t dht_key[TOX_PUBLIC_KEY_SIZE];
    tox_self_get_dht_id(tox1, dht_key);
    const uint16_t dht_port = tox_self_get_udp_port(tox1, nullptr);

    tox_bootstrap(tox2, "localhost", dht_port, dht_key, nullptr);
    tox_bootstrap(tox3, "localhost", dht_port, dht_key, nullptr);

    connected_t1 = 0;
    tox_callback_self_connection_status(tox1, tox_connection_status);
    tox_callback_friend_request(tox2, accept_friend_request);
    uint8_t address[TOX_ADDRESS_SIZE];
    tox_self_get_address(tox2, address);
    uint32_t test = tox_friend_add(tox3, address, (const uint8_t *)"Gentoo", 7, nullptr);
    ck_assert_msg(test == 0, "Failed to add friend error code: %i", test);

    uint8_t off = 1;

    while (1) {
        tox_iterate(tox1, nullptr);
        tox_iterate(tox2, nullptr);
        tox_iterate(tox3, nullptr);

        if (tox_self_get_connection_status(tox1) && tox_self_get_connection_status(tox2)
                && tox_self_get_connection_status(tox3)) {
            if (off) {
                printf("Toxes are online, took %ld seconds\n", time(nullptr) - cur_time);
                con_time = time(nullptr);
                off = 0;
            }

            if (tox_friend_get_connection_status(tox2, 0, nullptr) == TOX_CONNECTION_UDP
                    && tox_friend_get_connection_status(tox3, 0, nullptr) == TOX_CONNECTION_UDP) {
                break;
            }
        }

        c_sleep(ITERATION_INTERVAL);
    }

    ck_assert_msg(connected_t1, "Tox1 isn't connected. %u", connected_t1);
    printf("tox clients connected took %ld seconds\n", time(nullptr) - con_time);

    const size_t save_size1 = tox_get_savedata_size(tox2);
    ck_assert_msg(save_size1 != 0, "save is invalid size %u", (unsigned)save_size1);
    printf("%u\n", (unsigned)save_size1);
    VLA(uint8_t, save1, save_size1);
    tox_get_savedata(tox2, save1);
    tox_kill(tox2);

    struct Tox_Options *const options = tox_options_new(nullptr);
    tox_options_set_savedata_type(options, TOX_SAVEDATA_TYPE_TOX_SAVE);
    tox_options_set_savedata_data(options, save1, save_size1);
    tox_options_set_local_discovery_enabled(options, false);
    tox2 = tox_new_log(options, nullptr, &index[1]);
    cur_time = time(nullptr);
    off = 1;

    while (1) {
        tox_iterate(tox1, nullptr);
        tox_iterate(tox2, nullptr);
        tox_iterate(tox3, nullptr);

        if (tox_self_get_connection_status(tox1) && tox_self_get_connection_status(tox2)
                && tox_self_get_connection_status(tox3)) {
            if (off) {
                printf("Toxes are online again after reloading, took %ld seconds\n", time(nullptr) - cur_time);
                con_time = time(nullptr);
                off = 0;
            }

            if (tox_friend_get_connection_status(tox2, 0, nullptr) == TOX_CONNECTION_UDP
                    && tox_friend_get_connection_status(tox3, 0, nullptr) == TOX_CONNECTION_UDP) {
                break;
            }
        }

        c_sleep(ITERATION_INTERVAL);
    }

    printf("tox clients connected took %ld seconds\n", time(nullptr) - con_time);

    printf("test_few_clients succeeded, took %ld seconds\n", time(nullptr) - cur_time);

    tox_options_free(options);
    tox_kill(tox1);
    tox_kill(tox2);
    tox_kill(tox3);
}

int main(int argc, char *argv[])
{
    setvbuf(stdout, nullptr, _IONBF, 0);

    test_few_clients();
    return 0;
}
