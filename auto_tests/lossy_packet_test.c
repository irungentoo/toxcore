/* Tests that we can send lossy packets.
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

#define LOSSY_PACKET_FILLER 200

static void handle_lossy_packet(Tox *tox, uint32_t friend_number, const uint8_t *data, size_t length, void *user_data)
{
    uint8_t cmp_packet[TOX_MAX_CUSTOM_PACKET_SIZE];
    memset(cmp_packet, LOSSY_PACKET_FILLER, sizeof(cmp_packet));

    if (length == TOX_MAX_CUSTOM_PACKET_SIZE && memcmp(data, cmp_packet, sizeof(cmp_packet)) == 0) {
        bool *custom_packet_received = (bool *)user_data;
        *custom_packet_received = true;
    }
}

static void test_lossy_packet(void)
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

    tox_callback_friend_lossy_packet(tox2, &handle_lossy_packet);
    uint8_t packet[TOX_MAX_CUSTOM_PACKET_SIZE + 1];
    memset(packet, LOSSY_PACKET_FILLER, sizeof(packet));
    bool ret = tox_friend_send_lossy_packet(tox1, 0, packet, sizeof(packet), nullptr);
    ck_assert_msg(ret == false, "tox_friend_send_lossy_packet bigger fail %i", ret);
    ret = tox_friend_send_lossy_packet(tox1, 0, packet, TOX_MAX_CUSTOM_PACKET_SIZE, nullptr);
    ck_assert_msg(ret == true, "tox_friend_send_lossy_packet fail %i", ret);

    bool received_lossy_packet = false;

    while (!received_lossy_packet) {
        tox_iterate(tox1, nullptr);
        tox_iterate(tox2, &received_lossy_packet);
        c_sleep(200);
    }

    printf("test_lossy_packet succeeded, took %ld seconds\n", time(nullptr) - cur_time);

    tox_kill(tox1);
    tox_kill(tox2);
}

int main(int argc, char *argv[])
{
    setvbuf(stdout, nullptr, _IONBF, 0);

    test_lossy_packet();
    return 0;
}
