/* Auto Tests: Many clients.
 */

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include "../testing/misc_tools.h"
#include "../toxcore/crypto_core.h"
#include "../toxcore/tox.h"
#include "../toxcore/util.h"
#include "check_compat.h"

static void accept_friend_request(Tox *m, const uint8_t *public_key, const uint8_t *data, size_t length, void *userdata)
{
    if (length == 7 && memcmp("Gentoo", data, 7) == 0) {
        tox_friend_add_norequest(m, public_key, nullptr);
    }
}


#define TCP_TEST_NUM_TOXES 90
#define TCP_TEST_NUM_FRIENDS 50

static void test_many_clients(void)
{
    time_t cur_time = time(nullptr);
    Tox *toxes[TCP_TEST_NUM_TOXES];
    uint32_t index[TCP_TEST_NUM_TOXES];

    for (uint32_t i = 0; i < TCP_TEST_NUM_TOXES; ++i) {
        index[i] = i + 1;
        toxes[i] = tox_new_log(nullptr, nullptr, &index[i]);
        ck_assert_msg(toxes[i] != nullptr, "failed to create tox instances %u", i);
        tox_callback_friend_request(toxes[i], accept_friend_request);
    }

    struct {
        uint16_t tox1;
        uint16_t tox2;
    } pairs[TCP_TEST_NUM_FRIENDS];

    uint8_t address[TOX_ADDRESS_SIZE];

    uint32_t num_f = 0;

    for (uint32_t i = 0; i < TCP_TEST_NUM_TOXES; ++i) {
        num_f += tox_self_get_friend_list_size(toxes[i]);
    }

    ck_assert_msg(num_f == 0, "bad num friends: %u", num_f);

    for (uint32_t i = 0; i < TCP_TEST_NUM_FRIENDS; ++i) {
loop_top:
        pairs[i].tox1 = random_u32() % TCP_TEST_NUM_TOXES;
        pairs[i].tox2 = (pairs[i].tox1 + random_u32() % (TCP_TEST_NUM_TOXES - 1) + 1) % TCP_TEST_NUM_TOXES;

        for (uint32_t j = 0; j < i; ++j) {
            if (pairs[j].tox2 == pairs[i].tox1 && pairs[j].tox1 == pairs[i].tox2) {
                goto loop_top;
            }
        }

        tox_self_get_address(toxes[pairs[i].tox1], address);

        TOX_ERR_FRIEND_ADD test;
        uint32_t num = tox_friend_add(toxes[pairs[i].tox2], address, (const uint8_t *)"Gentoo", 7, &test);

        if (test == TOX_ERR_FRIEND_ADD_ALREADY_SENT) {
            goto loop_top;
        }

        uint8_t dht_key[TOX_PUBLIC_KEY_SIZE];
        tox_self_get_dht_id(toxes[pairs[i].tox1], dht_key);
        const uint16_t dht_port = tox_self_get_udp_port(toxes[pairs[i].tox1], nullptr);

        tox_bootstrap(toxes[pairs[i].tox2], "localhost", dht_port, dht_key, nullptr);

        ck_assert_msg(num != UINT32_MAX && test == TOX_ERR_FRIEND_ADD_OK, "failed to add friend error code: %i", test);
    }

    for (uint32_t i = 0; i < TCP_TEST_NUM_TOXES; ++i) {
        num_f += tox_self_get_friend_list_size(toxes[i]);
    }

    ck_assert_msg(num_f == TCP_TEST_NUM_FRIENDS, "bad num friends: %u", num_f);

    uint16_t last_count = 0;

    while (1) {
        uint16_t counter = 0;

        for (uint32_t i = 0; i < TCP_TEST_NUM_TOXES; ++i) {
            for (uint32_t j = 0; j < tox_self_get_friend_list_size(toxes[i]); ++j) {
                if (tox_friend_get_connection_status(toxes[i], j, nullptr) == TOX_CONNECTION_UDP) {
                    ++counter;
                }
            }
        }

        if (counter != last_count) {
            printf("many_clients got to %u\n", counter);
            last_count = counter;
        }

        if (counter == TCP_TEST_NUM_FRIENDS * 2) {
            break;
        }

        for (uint32_t i = 0; i < TCP_TEST_NUM_TOXES; ++i) {
            tox_iterate(toxes[i], nullptr);
        }

        c_sleep(50);
    }

    for (uint32_t i = 0; i < TCP_TEST_NUM_TOXES; ++i) {
        tox_kill(toxes[i]);
    }

    printf("test_many_clients succeeded, took %lu seconds\n", (unsigned long)(time(nullptr) - cur_time));
}

int main(void)
{
    setvbuf(stdout, nullptr, _IONBF, 0);

    test_many_clients();
    return 0;
}
