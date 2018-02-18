/* Tests that we can set our name.
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

#define NICKNAME "Gentoo"

static void nickchange_callback(Tox *tox, uint32_t friendnumber, const uint8_t *string, size_t length, void *userdata)
{
    ck_assert_msg(length == sizeof(NICKNAME) && memcmp(string, NICKNAME, sizeof(NICKNAME)) == 0, "Name not correct");
    bool *nickname_updated = (bool *)userdata;
    *nickname_updated = true;
}

static void test_set_name(void)
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
        c_sleep(ITERATION_INTERVAL);
    }

    printf("toxes are online, took %ld seconds\n", time(nullptr) - cur_time);
    const time_t con_time = time(nullptr);

    while (tox_friend_get_connection_status(tox1, 0, nullptr) != TOX_CONNECTION_UDP ||
            tox_friend_get_connection_status(tox2, 0, nullptr) != TOX_CONNECTION_UDP) {
        tox_iterate(tox1, nullptr);
        tox_iterate(tox2, nullptr);
        c_sleep(ITERATION_INTERVAL);
    }

    printf("tox clients connected took %ld seconds\n", time(nullptr) - con_time);

    tox_callback_friend_name(tox2, nickchange_callback);
    TOX_ERR_SET_INFO err_n;
    bool ret = tox_self_set_name(tox1, (const uint8_t *)NICKNAME, sizeof(NICKNAME), &err_n);
    ck_assert_msg(ret && err_n == TOX_ERR_SET_INFO_OK, "tox_self_set_name failed because %u\n", err_n);

    bool nickname_updated = false;

    while (!nickname_updated) {
        tox_iterate(tox1, nullptr);
        tox_iterate(tox2, &nickname_updated);
        c_sleep(ITERATION_INTERVAL);
    }

    ck_assert_msg(tox_friend_get_name_size(tox2, 0, nullptr) == sizeof(NICKNAME), "Name length not correct");
    uint8_t temp_name[sizeof(NICKNAME)];
    tox_friend_get_name(tox2, 0, temp_name, nullptr);
    ck_assert_msg(memcmp(temp_name, NICKNAME, sizeof(NICKNAME)) == 0, "Name not correct");

    printf("test_set_name succeeded, took %ld seconds\n", time(nullptr) - cur_time);

    tox_kill(tox1);
    tox_kill(tox2);
}

int main(int argc, char *argv[])
{
    setvbuf(stdout, nullptr, _IONBF, 0);

    test_set_name();
    return 0;
}
