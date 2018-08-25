#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <stdlib.h>
#include <string.h>

#include "../testing/misc_tools.h"
#include "../toxcore/mono_time.h"
#include "../toxcore/onion.h"
#include "../toxcore/onion_announce.h"
#include "../toxcore/onion_client.h"
#include "../toxcore/util.h"
#include "check_compat.h"

#ifndef USE_IPV6
#define USE_IPV6 1
#endif

static inline IP get_loopback()
{
    IP ip;
#if USE_IPV6
    ip.family = net_family_ipv6;
    ip.ip.v6 = get_ip6_loopback();
#else
    ip.family = net_family_ipv4;
    ip.ip.v4 = get_ip4_loopback();
#endif
    return ip;
}
static void do_onion(Onion *onion)
{
    mono_time_update(onion->mono_time);

    networking_poll(onion->net, nullptr);
    do_dht(onion->dht);
}

static int handled_test_1;
static int handle_test_1(void *object, IP_Port source, const uint8_t *packet, uint16_t length, void *userdata)
{
    Onion *onion = (Onion *)object;

    if (memcmp(packet, "\x83 Install Gentoo", sizeof("\x83 Install Gentoo")) != 0) {
        return 1;
    }

    if (send_onion_response(onion->net, source, (const uint8_t *)"\x84 install gentoo", sizeof("\x84 install gentoo"),
                            packet + sizeof("\x84 install gentoo")) == -1) {
        return 1;
    }

    handled_test_1 = 1;
    return 0;
}

static int handled_test_2;
static int handle_test_2(void *object, IP_Port source, const uint8_t *packet, uint16_t length, void *userdata)
{
    if (length != sizeof("\x84 install gentoo")) {
        return 1;
    }

    if (memcmp(packet, (const uint8_t *)"\x84 install gentoo", sizeof("\x84 install gentoo")) != 0) {
        return 1;
    }

    handled_test_2 = 1;
    return 0;
}
#if 0
void print_client_id(uint8_t *client_id, uint32_t length)
{
    uint32_t j;

    for (j = 0; j < length; j++) {
        printf("%02X", client_id[j]);
    }

    printf("\n");
}
#endif
static uint8_t sb_data[ONION_ANNOUNCE_SENDBACK_DATA_LENGTH];
static int handled_test_3;
static uint8_t test_3_pub_key[CRYPTO_PUBLIC_KEY_SIZE];
static uint8_t test_3_ping_id[CRYPTO_SHA256_SIZE];
static int handle_test_3(void *object, IP_Port source, const uint8_t *packet, uint16_t length, void *userdata)
{
    Onion *onion = (Onion *)object;

    if (length != (1 + CRYPTO_NONCE_SIZE + ONION_ANNOUNCE_SENDBACK_DATA_LENGTH + 1 + CRYPTO_SHA256_SIZE +
                   CRYPTO_MAC_SIZE)) {
        return 1;
    }

    uint8_t plain[1 + CRYPTO_SHA256_SIZE];
#if 0
    print_client_id(packet, length);
#endif
    int len = decrypt_data(test_3_pub_key, dht_get_self_secret_key(onion->dht),
                           packet + 1 + ONION_ANNOUNCE_SENDBACK_DATA_LENGTH,
                           packet + 1 + ONION_ANNOUNCE_SENDBACK_DATA_LENGTH + CRYPTO_NONCE_SIZE,
                           1 + CRYPTO_SHA256_SIZE + CRYPTO_MAC_SIZE, plain);

    if (len == -1) {
        return 1;
    }


    if (memcmp(packet + 1, sb_data, ONION_ANNOUNCE_SENDBACK_DATA_LENGTH) != 0) {
        return 1;
    }

    memcpy(test_3_ping_id, plain + 1, CRYPTO_SHA256_SIZE);
#if 0
    print_client_id(test_3_ping_id, sizeof(test_3_ping_id));
#endif
    handled_test_3 = 1;
    return 0;
}

static uint8_t nonce[CRYPTO_NONCE_SIZE];
static int handled_test_4;
static int handle_test_4(void *object, IP_Port source, const uint8_t *packet, uint16_t length, void *userdata)
{
    Onion *onion = (Onion *)object;

    if (length != (1 + CRYPTO_NONCE_SIZE + CRYPTO_PUBLIC_KEY_SIZE + sizeof("Install gentoo") +
                   CRYPTO_MAC_SIZE)) {
        return 1;
    }

    uint8_t plain[sizeof("Install gentoo")] = {0};

    if (memcmp(nonce, packet + 1, CRYPTO_NONCE_SIZE) != 0) {
        return 1;
    }

    int len = decrypt_data(packet + 1 + CRYPTO_NONCE_SIZE, dht_get_self_secret_key(onion->dht), packet + 1,
                           packet + 1 + CRYPTO_NONCE_SIZE + CRYPTO_PUBLIC_KEY_SIZE, sizeof("Install gentoo") + CRYPTO_MAC_SIZE, plain);

    if (len == -1) {
        return 1;
    }

    if (memcmp(plain, "Install gentoo", sizeof("Install gentoo")) != 0) {
        return 1;
    }

    handled_test_4 = 1;
    return 0;
}

static void test_basic(void)
{
    uint32_t index[] = { 1, 2, 3 };
    Logger *log1 = logger_new();
    logger_callback_log(log1, (logger_cb *)print_debug_log, nullptr, &index[0]);
    Logger *log2 = logger_new();
    logger_callback_log(log2, (logger_cb *)print_debug_log, nullptr, &index[1]);

    Mono_Time *mono_time1 = mono_time_new();
    Mono_Time *mono_time2 = mono_time_new();

    IP ip = get_loopback();
    Onion *onion1 = new_onion(mono_time1, new_dht(log1, mono_time1, new_networking(log1, ip, 36567), true));
    Onion *onion2 = new_onion(mono_time2, new_dht(log2, mono_time2, new_networking(log2, ip, 36568), true));
    ck_assert_msg((onion1 != nullptr) && (onion2 != nullptr), "Onion failed initializing.");
    networking_registerhandler(onion2->net, NET_PACKET_ANNOUNCE_REQUEST, &handle_test_1, onion2);

    IP_Port on1 = {ip, net_port(onion1->net)};
    Node_format n1;
    memcpy(n1.public_key, dht_get_self_public_key(onion1->dht), CRYPTO_PUBLIC_KEY_SIZE);
    n1.ip_port = on1;

    IP_Port on2 = {ip, net_port(onion2->net)};
    Node_format n2;
    memcpy(n2.public_key, dht_get_self_public_key(onion2->dht), CRYPTO_PUBLIC_KEY_SIZE);
    n2.ip_port = on2;

    Node_format nodes[4];
    nodes[0] = n1;
    nodes[1] = n2;
    nodes[2] = n1;
    nodes[3] = n2;
    Onion_Path path;
    create_onion_path(onion1->dht, &path, nodes);
    int ret = send_onion_packet(onion1->net, &path, nodes[3].ip_port, (const uint8_t *)"\x83 Install Gentoo",
                                sizeof("\x83 Install Gentoo"));
    ck_assert_msg(ret == 0, "Failed to create/send onion packet.");

    handled_test_1 = 0;

    do {
        do_onion(onion1);
        do_onion(onion2);
    } while (handled_test_1 == 0);

    networking_registerhandler(onion1->net, NET_PACKET_ANNOUNCE_RESPONSE, &handle_test_2, onion1);
    handled_test_2 = 0;

    do {
        do_onion(onion1);
        do_onion(onion2);
    } while (handled_test_2 == 0);

    Onion_Announce *onion1_a = new_onion_announce(mono_time1, onion1->dht);
    Onion_Announce *onion2_a = new_onion_announce(mono_time2, onion2->dht);
    networking_registerhandler(onion1->net, NET_PACKET_ANNOUNCE_RESPONSE, &handle_test_3, onion1);
    ck_assert_msg((onion1_a != nullptr) && (onion2_a != nullptr), "Onion_Announce failed initializing.");
    uint8_t zeroes[64] = {0};
    random_bytes(sb_data, sizeof(sb_data));
    uint64_t s;
    memcpy(&s, sb_data, sizeof(uint64_t));
    memcpy(test_3_pub_key, nodes[3].public_key, CRYPTO_PUBLIC_KEY_SIZE);
    ret = send_announce_request(onion1->net, &path, nodes[3],
                                dht_get_self_public_key(onion1->dht),
                                dht_get_self_secret_key(onion1->dht),
                                zeroes,
                                dht_get_self_public_key(onion1->dht),
                                dht_get_self_public_key(onion1->dht), s);
    ck_assert_msg(ret == 0, "Failed to create/send onion announce_request packet.");
    handled_test_3 = 0;

    do {
        do_onion(onion1);
        do_onion(onion2);
        c_sleep(50);
    } while (handled_test_3 == 0);

    random_bytes(sb_data, sizeof(sb_data));
    memcpy(&s, sb_data, sizeof(uint64_t));
    memcpy(onion_announce_entry_public_key(onion2_a, 1), dht_get_self_public_key(onion2->dht), CRYPTO_PUBLIC_KEY_SIZE);
    onion_announce_entry_set_time(onion2_a, 1, mono_time_get(mono_time2));
    networking_registerhandler(onion1->net, NET_PACKET_ONION_DATA_RESPONSE, &handle_test_4, onion1);
    send_announce_request(onion1->net, &path, nodes[3],
                          dht_get_self_public_key(onion1->dht),
                          dht_get_self_secret_key(onion1->dht),
                          test_3_ping_id,
                          dht_get_self_public_key(onion1->dht),
                          dht_get_self_public_key(onion1->dht), s);

    do {
        do_onion(onion1);
        do_onion(onion2);
        c_sleep(50);
    } while (memcmp(onion_announce_entry_public_key(onion2_a, ONION_ANNOUNCE_MAX_ENTRIES - 2),
                    dht_get_self_public_key(onion1->dht),
                    CRYPTO_PUBLIC_KEY_SIZE) != 0);

    c_sleep(1000);
    Logger *log3 = logger_new();
    logger_callback_log(log3, (logger_cb *)print_debug_log, nullptr, &index[2]);

    Mono_Time *mono_time3 = mono_time_new();

    Onion *onion3 = new_onion(mono_time3, new_dht(log3, mono_time3, new_networking(log3, ip, 36569), true));
    ck_assert_msg((onion3 != nullptr), "Onion failed initializing.");

    random_nonce(nonce);
    ret = send_data_request(onion3->net, &path, nodes[3].ip_port,
                            dht_get_self_public_key(onion1->dht),
                            dht_get_self_public_key(onion1->dht),
                            nonce, (const uint8_t *)"Install gentoo", sizeof("Install gentoo"));
    ck_assert_msg(ret == 0, "Failed to create/send onion data_request packet.");
    handled_test_4 = 0;

    do {
        do_onion(onion1);
        do_onion(onion2);
        c_sleep(50);
    } while (handled_test_4 == 0);

    kill_onion_announce(onion2_a);
    kill_onion_announce(onion1_a);

    {
        Onion *onion = onion3;

        Networking_Core *net = dht_get_net(onion->dht);
        DHT *dht = onion->dht;
        kill_onion(onion);
        kill_dht(dht);
        kill_networking(net);
        mono_time_free(mono_time3);
        logger_kill(log3);
    }

    {
        Onion *onion = onion2;

        Networking_Core *net = dht_get_net(onion->dht);
        DHT *dht = onion->dht;
        kill_onion(onion);
        kill_dht(dht);
        kill_networking(net);
        mono_time_free(mono_time2);
        logger_kill(log2);
    }

    {
        Onion *onion = onion1;

        Networking_Core *net = dht_get_net(onion->dht);
        DHT *dht = onion->dht;
        kill_onion(onion);
        kill_dht(dht);
        kill_networking(net);
        mono_time_free(mono_time1);
        logger_kill(log1);
    }
}

typedef struct {
    Logger *log;
    Mono_Time *mono_time;
    Onion *onion;
    Onion_Announce *onion_a;
    Onion_Client *onion_c;
} Onions;

static Onions *new_onions(uint16_t port, uint32_t *index)
{
    IP ip = get_loopback();
    ip.ip.v6.uint8[15] = 1;
    Onions *on = (Onions *)malloc(sizeof(Onions));

    if (!on) {
        return nullptr;
    }

    on->log = logger_new();

    if (!on->log) {
        free(on);
        return nullptr;
    }

    logger_callback_log(on->log, (logger_cb *)print_debug_log, nullptr, index);

    on->mono_time = mono_time_new();

    if (!on->mono_time) {
        logger_kill(on->log);
        free(on);
        return nullptr;
    }

    Networking_Core *net = new_networking(on->log, ip, port);

    if (!net) {
        mono_time_free(on->mono_time);
        logger_kill(on->log);
        free(on);
        return nullptr;
    }

    DHT *dht = new_dht(on->log, on->mono_time, net, true);

    if (!dht) {
        kill_networking(net);
        mono_time_free(on->mono_time);
        logger_kill(on->log);
        free(on);
        return nullptr;
    }

    on->onion = new_onion(on->mono_time, dht);

    if (!on->onion) {
        kill_dht(dht);
        kill_networking(net);
        mono_time_free(on->mono_time);
        logger_kill(on->log);
        free(on);
        return nullptr;
    }

    on->onion_a = new_onion_announce(on->mono_time, dht);

    if (!on->onion_a) {
        kill_onion(on->onion);
        kill_dht(dht);
        kill_networking(net);
        mono_time_free(on->mono_time);
        logger_kill(on->log);
        free(on);
        return nullptr;
    }

    TCP_Proxy_Info inf = {{{{0}}}};
    on->onion_c = new_onion_client(on->mono_time, new_net_crypto(on->log, on->mono_time, dht, &inf));

    if (!on->onion_c) {
        kill_onion_announce(on->onion_a);
        kill_onion(on->onion);
        kill_dht(dht);
        kill_networking(net);
        mono_time_free(on->mono_time);
        logger_kill(on->log);
        free(on);
        return nullptr;
    }

    return on;
}

static void do_onions(Onions *on)
{
    mono_time_update(on->mono_time);

    networking_poll(on->onion->net, nullptr);
    do_dht(on->onion->dht);
    do_onion_client(on->onion_c);
}

static void kill_onions(Onions *on)
{
    Networking_Core *net = dht_get_net(on->onion->dht);
    DHT *dht = on->onion->dht;
    Net_Crypto *c = onion_get_net_crypto(on->onion_c);
    kill_onion_client(on->onion_c);
    kill_onion_announce(on->onion_a);
    kill_onion(on->onion);
    kill_net_crypto(c);
    kill_dht(dht);
    kill_networking(net);
    mono_time_free(on->mono_time);
    logger_kill(on->log);
    free(on);
}

#define NUM_ONIONS 50
#define NUM_FIRST 7
#define NUM_LAST 37

static bool first_ip, last_ip;
static void dht_ip_callback(void *object, int32_t number, IP_Port ip_port)
{
    if (NUM_FIRST == number) {
        first_ip = 1;
        return;
    }

    if (NUM_LAST == number) {
        last_ip = 1;
        return;
    }

    ck_abort_msg("Error.");
}

static bool first, last;
static uint8_t first_dht_pk[CRYPTO_PUBLIC_KEY_SIZE];
static uint8_t last_dht_pk[CRYPTO_PUBLIC_KEY_SIZE];

static void dht_pk_callback(void *object, int32_t number, const uint8_t *dht_public_key, void *userdata)
{
    if ((NUM_FIRST == number && !first) || (NUM_LAST == number && !last)) {
        Onions *on = (Onions *)object;
        uint16_t count = 0;
        int ret = dht_addfriend(on->onion->dht, dht_public_key, &dht_ip_callback, object, number, &count);
        ck_assert_msg(ret == 0, "dht_addfriend() did not return 0");
        ck_assert_msg(count == 1, "Count not 1, count is %u", count);

        if (NUM_FIRST == number && !first) {
            first = 1;

            if (memcmp(dht_public_key, last_dht_pk, CRYPTO_PUBLIC_KEY_SIZE) != 0) {
                ck_abort_msg("Error wrong dht key.");
            }

            return;
        }

        if (NUM_LAST == number && !last) {
            last = 1;

            if (memcmp(dht_public_key, first_dht_pk, CRYPTO_PUBLIC_KEY_SIZE) != 0) {
                ck_abort_msg("Error wrong dht key.");
            }

            return;
        }

        ck_abort_msg("Error.");
    }
}

static void test_announce(void)
{
    uint32_t i, j;
    uint32_t index[NUM_ONIONS];
    Onions *onions[NUM_ONIONS];

    for (i = 0; i < NUM_ONIONS; ++i) {
        index[i] = i + 1;
        onions[i] = new_onions(i + 36655, &index[i]);
        ck_assert_msg(onions[i] != nullptr, "Failed to create onions. %u", i);
    }

    IP ip = get_loopback();

    for (i = 3; i < NUM_ONIONS; ++i) {
        IP_Port ip_port = {ip, net_port(onions[i - 1]->onion->net)};
        dht_bootstrap(onions[i]->onion->dht, ip_port, dht_get_self_public_key(onions[i - 1]->onion->dht));
        IP_Port ip_port1 = {ip, net_port(onions[i - 2]->onion->net)};
        dht_bootstrap(onions[i]->onion->dht, ip_port1, dht_get_self_public_key(onions[i - 2]->onion->dht));
        IP_Port ip_port2 = {ip, net_port(onions[i - 3]->onion->net)};
        dht_bootstrap(onions[i]->onion->dht, ip_port2, dht_get_self_public_key(onions[i - 3]->onion->dht));
    }

    uint32_t connected = 0;

    do {
        connected = 0;

        for (i = 0; i < NUM_ONIONS; ++i) {
            do_onions(onions[i]);
            connected += dht_isconnected(onions[i]->onion->dht);
        }

        c_sleep(50);
    } while (connected != NUM_ONIONS);

    printf("connected\n");

    for (i = 0; i < 25 * 2; ++i) {
        for (j = 0; j < NUM_ONIONS; ++j) {
            do_onions(onions[j]);
        }

        c_sleep(50);
    }

    memcpy(first_dht_pk, dht_get_self_public_key(onions[NUM_FIRST]->onion->dht), CRYPTO_PUBLIC_KEY_SIZE);
    memcpy(last_dht_pk, dht_get_self_public_key(onions[NUM_LAST]->onion->dht), CRYPTO_PUBLIC_KEY_SIZE);

    printf("adding friend\n");
    int frnum_f = onion_addfriend(onions[NUM_FIRST]->onion_c,
                                  nc_get_self_public_key(onion_get_net_crypto(onions[NUM_LAST]->onion_c)));
    int frnum = onion_addfriend(onions[NUM_LAST]->onion_c,
                                nc_get_self_public_key(onion_get_net_crypto(onions[NUM_FIRST]->onion_c)));

    onion_dht_pk_callback(onions[NUM_FIRST]->onion_c, frnum_f, &dht_pk_callback, onions[NUM_FIRST], NUM_FIRST);
    onion_dht_pk_callback(onions[NUM_LAST]->onion_c, frnum, &dht_pk_callback, onions[NUM_LAST], NUM_LAST);

    IP_Port ip_port;

    do {
        for (i = 0; i < NUM_ONIONS; ++i) {
            do_onions(onions[i]);
        }

        c_sleep(50);
    } while (!first || !last);

    printf("Waiting for ips\n");

    do {
        for (i = 0; i < NUM_ONIONS; ++i) {
            do_onions(onions[i]);
        }

        c_sleep(50);
    } while (!first_ip || !last_ip);

    onion_getfriendip(onions[NUM_LAST]->onion_c, frnum, &ip_port);
    ck_assert_msg(ip_port.port == net_port(onions[NUM_FIRST]->onion->net), "Port in returned ip not correct.");

    for (i = 0; i < NUM_ONIONS; ++i) {
        kill_onions(onions[i]);
    }
}

int main(void)
{
    setvbuf(stdout, nullptr, _IONBF, 0);

    test_basic();
    test_announce();

    return 0;
}
