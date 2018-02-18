/* Tests that we can add friends.
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

#define FR_MESSAGE "Gentoo"

static void accept_friend_request(Tox *tox, const uint8_t *public_key, const uint8_t *data, size_t length,
                                  void *userdata)
{
    ck_assert_msg(length == sizeof(FR_MESSAGE) && memcmp(FR_MESSAGE, data, sizeof(FR_MESSAGE)) == 0,
                  "unexpected friend request message");
    tox_friend_add_norequest(tox, public_key, nullptr);
}

static void test_friend_request(void)
{
    printf("initialising 2 toxes\n");
    uint32_t index[] = { 1, 2 };
    const time_t cur_time = time(nullptr);
    Tox *const tox1 = tox_new_log(nullptr, nullptr, &index[0]);
    Tox *const tox2 = tox_new_log(nullptr, nullptr, &index[1]);

    ck_assert_msg(tox1 && tox2, "failed to create 2 tox instances");

    printf("bootstrapping tox2 off tox1\n");
    uint8_t dht_key[TOX_PUBLIC_KEY_SIZE];
    tox_self_get_dht_id(tox1, dht_key);
    const uint16_t dht_port = tox_self_get_udp_port(tox1, nullptr);

    tox_bootstrap(tox2, "localhost", dht_port, dht_key, nullptr);

    while (tox_self_get_connection_status(tox1) == TOX_CONNECTION_NONE ||
            tox_self_get_connection_status(tox2) == TOX_CONNECTION_NONE) {
        tox_iterate(tox1, nullptr);
        tox_iterate(tox2, nullptr);

        c_sleep(ITERATION_INTERVAL);
    }

    printf("toxes are online, took %ld seconds\n", time(nullptr) - cur_time);
    const time_t con_time = time(nullptr);

    printf("tox1 adds tox2 as friend, tox2 accepts\n");
    tox_callback_friend_request(tox2, accept_friend_request);

    uint8_t address[TOX_ADDRESS_SIZE];
    tox_self_get_address(tox2, address);

    const uint32_t test = tox_friend_add(tox1, address, (const uint8_t *)FR_MESSAGE, sizeof(FR_MESSAGE), nullptr);
    ck_assert_msg(test == 0, "Failed to add friend error code: %i", test);

    while (tox_friend_get_connection_status(tox1, 0, nullptr) != TOX_CONNECTION_UDP ||
            tox_friend_get_connection_status(tox2, 0, nullptr) != TOX_CONNECTION_UDP) {
        tox_iterate(tox1, nullptr);
        tox_iterate(tox2, nullptr);

        c_sleep(ITERATION_INTERVAL);
    }

    printf("tox clients connected took %ld seconds\n", time(nullptr) - con_time);
    printf("test_friend_request succeeded, took %ld seconds\n", time(nullptr) - cur_time);

    tox_kill(tox1);
    tox_kill(tox2);
}

int main(int argc, char *argv[])
{
    setvbuf(stdout, nullptr, _IONBF, 0);

    test_friend_request();
    return 0;
}
