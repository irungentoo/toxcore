/* Tests that our typing notifications work.
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

static void typing_callback(Tox *m, uint32_t friendnumber, bool typing, void *userdata)
{
    bool *is_typing = (bool *)userdata;
    *is_typing = typing;
}

static void test_typing(void)
{
    printf("initialising 2 toxes\n");
    uint32_t index[] = { 1, 2 };
    const time_t cur_time = time(nullptr);
    Tox *const tox1 = tox_new_log(nullptr, nullptr, &index[0]);
    Tox *const tox2 = tox_new_log(nullptr, nullptr, &index[1]);

    ck_assert_msg(tox1 && tox2, "failed to create 2 tox instances");

    printf("tox1 adds tox2 as friend, tox2 adds tox1\n");
    uint8_t public_key[TOX_PUBLIC_KEY_SIZE];
    tox_self_get_public_key(tox2, public_key);
    tox_friend_add_norequest(tox1, public_key, nullptr);
    tox_self_get_public_key(tox1, public_key);
    tox_friend_add_norequest(tox2, public_key, nullptr);

    printf("bootstrapping tox2 off tox1\n");
    uint8_t dht_key[TOX_PUBLIC_KEY_SIZE];
    tox_self_get_dht_id(tox1, dht_key);
    const uint16_t dht_port = tox_self_get_udp_port(tox1, nullptr);

    tox_bootstrap(tox2, "localhost", dht_port, dht_key, nullptr);

    while (tox_self_get_connection_status(tox1) == TOX_CONNECTION_NONE ||
            tox_self_get_connection_status(tox2) == TOX_CONNECTION_NONE) {
        tox_iterate(tox1, nullptr);
        tox_iterate(tox2, nullptr);

        c_sleep(200);
    }

    printf("toxes are online, took %ld seconds\n", time(nullptr) - cur_time);
    const time_t con_time = time(nullptr);

    while (tox_friend_get_connection_status(tox1, 0, nullptr) != TOX_CONNECTION_UDP ||
            tox_friend_get_connection_status(tox2, 0, nullptr) != TOX_CONNECTION_UDP) {
        tox_iterate(tox1, nullptr);
        tox_iterate(tox2, nullptr);

        c_sleep(200);
    }

    printf("tox clients connected took %ld seconds\n", time(nullptr) - con_time);

    tox_callback_friend_typing(tox2, &typing_callback);
    tox_self_set_typing(tox1, 0, true, nullptr);

    bool is_typing = false;

    while (!is_typing) {
        tox_iterate(tox1, nullptr);
        tox_iterate(tox2, &is_typing);
        c_sleep(200);
    }

    ck_assert_msg(tox_friend_get_typing(tox2, 0, nullptr) == 1, "Typing failure");
    tox_self_set_typing(tox1, 0, false, nullptr);

    while (is_typing) {
        tox_iterate(tox1, nullptr);
        tox_iterate(tox2, &is_typing);
        c_sleep(200);
    }

    TOX_ERR_FRIEND_QUERY err_t;
    ck_assert_msg(tox_friend_get_typing(tox2, 0, &err_t) == 0, "Typing failure");
    ck_assert_msg(err_t == TOX_ERR_FRIEND_QUERY_OK, "Typing failure");

    printf("test_typing succeeded, took %ld seconds\n", time(nullptr) - cur_time);

    tox_kill(tox1);
    tox_kill(tox2);
}

int main(int argc, char *argv[])
{
    setvbuf(stdout, nullptr, _IONBF, 0);

    test_typing();
    return 0;
}
