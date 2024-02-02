#include <stdint.h>
#include <string.h>

#include "../toxcore/announce.h"
#include "../toxcore/tox.h"
#include "../testing/misc_tools.h"
#include "../toxcore/mono_time.h"
#include "../toxcore/forwarding.h"
#include "../toxcore/net_crypto.h"
#include "../toxcore/util.h"
#include "auto_test_support.h"
#include "check_compat.h"

static void test_bucketnum(void)
{
    const Random *rng = os_random();
    ck_assert(rng != nullptr);
    uint8_t key1[CRYPTO_PUBLIC_KEY_SIZE], key2[CRYPTO_PUBLIC_KEY_SIZE];
    random_bytes(rng, key1, sizeof(key1));
    memcpy(key2, key1, CRYPTO_PUBLIC_KEY_SIZE);

    ck_assert_msg(announce_get_bucketnum(key1, key2) == 0, "Bad bucketnum");

    key2[4] ^= 0x09;
    key2[5] ^= 0xc5;

    ck_assert_msg(announce_get_bucketnum(key1, key2) == 7, "Bad bucketnum");

    key2[4] ^= 0x09;

    ck_assert_msg(announce_get_bucketnum(key1, key2) == 17, "Bad bucketnum");

    key2[5] ^= 0xc5;
    key2[31] ^= 0x09;

    ck_assert_msg(announce_get_bucketnum(key1, key2) == 4, "Bad bucketnum");
}

typedef struct Announce_Test_Data {
    uint8_t data[MAX_ANNOUNCEMENT_SIZE];
    uint16_t length;
    bool passed;
} Announce_Test_Data;

static void test_announce_data(void *object, const uint8_t *data, uint16_t length)
{
    Announce_Test_Data *test_data = (Announce_Test_Data *) object;
    test_data->passed = test_data->length == length && memcmp(test_data->data, data, length) == 0;
}

static void test_store_data(void)
{
    const Random *rng = os_random();
    ck_assert(rng != nullptr);
    const Network *ns = os_network();
    ck_assert(ns != nullptr);
    const Memory *mem = os_memory();
    ck_assert(mem != nullptr);

    Logger *log = logger_new();
    ck_assert(log != nullptr);
    logger_callback_log(log, print_debug_logger, nullptr, nullptr);
    Mono_Time *mono_time = mono_time_new(mem, nullptr, nullptr);
    ck_assert(mono_time != nullptr);
    Networking_Core *net = new_networking_no_udp(log, mem, ns);
    ck_assert(net != nullptr);
    DHT *dht = new_dht(log, mem, rng, ns, mono_time, net, true, true);
    ck_assert(dht != nullptr);
    Forwarding *forwarding = new_forwarding(log, rng, mono_time, dht);
    ck_assert(forwarding != nullptr);
    Announcements *announce = new_announcements(log, mem, rng, mono_time, forwarding);
    ck_assert(announce != nullptr);

    /* Just to prevent CI from complaining that set_synch_offset is unused: */
    announce_set_synch_offset(announce, 0);

    Announce_Test_Data test_data;
    random_bytes(rng, test_data.data, sizeof(test_data.data));
    test_data.length = sizeof(test_data.data);

    uint8_t key[CRYPTO_PUBLIC_KEY_SIZE];
    random_bytes(rng, key, sizeof(key));

    ck_assert_msg(!announce_on_stored(announce, key, nullptr, nullptr), "Unstored announcement exists");

    ck_assert_msg(announce_store_data(announce, key, test_data.data, sizeof(test_data.data),
                                      MAX_MAX_ANNOUNCEMENT_TIMEOUT), "Failed to store announcement");

    ck_assert_msg(announce_on_stored(announce, key, test_announce_data, &test_data), "Failed to get stored announcement");

    ck_assert_msg(test_data.passed, "Bad stored announcement data");

    const uint8_t *const base = dht_get_self_public_key(dht);
    ck_assert_msg(announce_store_data(announce, base, test_data.data, sizeof(test_data.data), 1), "failed to store base");

    uint8_t test_keys[ANNOUNCE_BUCKET_SIZE + 1][CRYPTO_PUBLIC_KEY_SIZE];

    for (uint8_t i = 0; i < ANNOUNCE_BUCKET_SIZE + 1; ++i) {
        memcpy(test_keys[i], base, CRYPTO_PUBLIC_KEY_SIZE);
        test_keys[i][i] ^= 1;
        ck_assert_msg(announce_store_data(announce, test_keys[i], test_data.data, sizeof(test_data.data), 1),
                      "Failed to store announcement %d", i);
    }

    ck_assert_msg(announce_on_stored(announce, base, nullptr, nullptr), "base was evicted");
    ck_assert_msg(!announce_on_stored(announce, test_keys[0], nullptr, nullptr), "furthest was not evicted");
    ck_assert_msg(!announce_store_data(announce, test_keys[0], nullptr, 0, 1), "furthest evicted closer");

    kill_announcements(announce);
    kill_forwarding(forwarding);
    kill_dht(dht);
    kill_networking(net);
    mono_time_free(mem, mono_time);
    logger_kill(log);
}

static void basic_announce_tests(void)
{
    test_bucketnum();
    test_store_data();
}

int main(void)
{
    setvbuf(stdout, nullptr, _IONBF, 0);

    basic_announce_tests();
    return 0;
}
