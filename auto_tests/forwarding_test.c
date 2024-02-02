#include <assert.h>
#include <stdlib.h>
#include <string.h>

#include "../toxcore/tox.h"
#include "../toxcore/announce.h"
#include "../testing/misc_tools.h"
#include "../toxcore/mono_time.h"
#include "../toxcore/forwarding.h"
#include "../toxcore/net_crypto.h"
#include "../toxcore/util.h"
#include "auto_test_support.h"
#include "check_compat.h"

#ifndef USE_IPV6
#define USE_IPV6 1
#endif

static inline IP get_loopback(void)
{
    IP ip;
#if USE_IPV6
    ip.family = net_family_ipv6();
    ip.ip.v6 = get_ip6_loopback();
#else
    ip.family = net_family_ipv4();
    ip.ip.v4 = get_ip4_loopback();
#endif
    return ip;
}

#define NUM_FORWARDER 20
#define NUM_FORWARDER_TCP 5
#define NUM_FORWARDER_DHT (NUM_FORWARDER - NUM_FORWARDER_TCP)
#define NUM_FORWARDING_ITERATIONS 1
#define FORWARD_SEND_INTERVAL 2
#define FORWARDING_BASE_PORT 36571

typedef struct Test_Data {
    Networking_Core *net;
    uint32_t send_back;
    uint64_t sent;
    bool returned;
} Test_Data;

static void test_forwarded_request_cb(void *object, const IP_Port *forwarder,
                                      const uint8_t *sendback, uint16_t sendback_length,
                                      const uint8_t *data, uint16_t length, void *userdata)
{
    const Test_Data *test_data = (const Test_Data *)object;
    const uint8_t *index = (const uint8_t *)userdata;

    if (length != 12 || memcmp("hello:  ", data, 8) != 0) {
        printf("[%u] got unexpected data of length %d\n", *index, length);
        return;
    }

    uint8_t reply[12];
    memcpy(reply, "reply:  ", 8);
    memcpy(reply + 8, data + 8, 4);
    ck_assert_msg(forward_reply(test_data->net, forwarder, sendback, sendback_length, reply, 12),
                  "[%u] forward_reply failed", *index);
}

static void test_forwarded_response_cb(void *object,
                                       const uint8_t *data, uint16_t length, void *userdata)
{
    Test_Data *test_data = (Test_Data *)object;
    const uint8_t *index = (const uint8_t *)userdata;

    if (length != 12 || memcmp("reply:  ", data, 8) != 0) {
        printf("[%u] got unexpected data of length %d\n", *index, length);
        return;
    }

    uint32_t send_back;
    net_unpack_u32(data + 8, &send_back);

    if (test_data->send_back == send_back) {
        test_data->returned = true;
    }
}

static bool all_returned(Test_Data *test_data)
{
    for (uint32_t i = 0; i < NUM_FORWARDER; ++i) {
        if (!test_data[i].returned) {
            return false;
        }
    }

    return true;
}

typedef struct Forwarding_Subtox {
    Logger *log;
    Mono_Time *mono_time;
    Networking_Core *net;
    DHT *dht;
    Net_Crypto *c;
    Forwarding *forwarding;
    Announcements *announce;
} Forwarding_Subtox;

static Forwarding_Subtox *new_forwarding_subtox(const Memory *mem, bool no_udp, uint32_t *index, uint16_t port)
{
    const Random *rng = os_random();
    ck_assert(rng != nullptr);
    const Network *ns = os_network();
    ck_assert(ns != nullptr);

    Forwarding_Subtox *subtox = (Forwarding_Subtox *)calloc(1, sizeof(Forwarding_Subtox));
    ck_assert(subtox != nullptr);

    subtox->log = logger_new();
    ck_assert(subtox->log != nullptr);
    logger_callback_log(subtox->log, print_debug_logger, nullptr, index);
    subtox->mono_time = mono_time_new(mem, nullptr, nullptr);

    if (no_udp) {
        subtox->net = new_networking_no_udp(subtox->log, mem, ns);
    } else {
        const IP ip = get_loopback();
        subtox->net = new_networking_ex(subtox->log, mem, ns, &ip, port, port, nullptr);
    }

    subtox->dht = new_dht(subtox->log, mem, rng, ns, subtox->mono_time, subtox->net, true, true);

    const TCP_Proxy_Info inf = {{{{0}}}};
    subtox->c = new_net_crypto(subtox->log, mem, rng, ns, subtox->mono_time, subtox->dht, &inf);

    subtox->forwarding = new_forwarding(subtox->log, rng, subtox->mono_time, subtox->dht);
    ck_assert(subtox->forwarding != nullptr);

    subtox->announce = new_announcements(subtox->log, mem, rng, subtox->mono_time, subtox->forwarding);
    ck_assert(subtox->announce != nullptr);

    return subtox;
}

static void kill_forwarding_subtox(const Memory *mem, Forwarding_Subtox *subtox)
{
    kill_announcements(subtox->announce);
    kill_forwarding(subtox->forwarding);
    kill_net_crypto(subtox->c);
    kill_dht(subtox->dht);
    kill_networking(subtox->net);
    mono_time_free(mem, subtox->mono_time);
    logger_kill(subtox->log);
    free(subtox);
}

static void test_forwarding(void)
{
    const Memory *mem = os_memory();
    ck_assert(mem != nullptr);
    const Random *rng = os_random();
    ck_assert(rng != nullptr);
    const Network *ns = os_network();
    ck_assert(ns != nullptr);

    uint32_t index[NUM_FORWARDER];
    Forwarding_Subtox *subtoxes[NUM_FORWARDER];
    Test_Data test_data[NUM_FORWARDER];

    const IP ip = get_loopback();

    for (uint32_t i = 0; i < NUM_FORWARDER; ++i) {
        index[i] = i + 1;
        subtoxes[i] = new_forwarding_subtox(mem, i < NUM_FORWARDER_TCP, &index[i], FORWARDING_BASE_PORT + i);

        test_data[i].net = subtoxes[i]->net;
        test_data[i].send_back = 0;
        test_data[i].sent = 0;
        test_data[i].returned = false;
        set_callback_forwarded_request(subtoxes[i]->forwarding, test_forwarded_request_cb, &test_data[i]);
        set_callback_forwarded_response(subtoxes[i]->forwarding, test_forwarded_response_cb, &test_data[i]);
        set_forwarding_packet_tcp_connection_callback(nc_get_tcp_c(subtoxes[i]->c), test_forwarded_response_cb, &test_data[i]);
    }

    printf("testing forwarding via tcp relays and dht\n");

    struct Tox_Options *opts = tox_options_new(nullptr);
    uint16_t forwarder_tcp_relay_port = 36570;
    Tox *relay = nullptr;
    // Try a few different ports.
    for (uint8_t i = 0; i < 100; ++i) {
        tox_options_set_tcp_port(opts, forwarder_tcp_relay_port);
        relay = tox_new_log(opts, nullptr, nullptr);
        if (relay != nullptr) {
            break;
        }
        ++forwarder_tcp_relay_port;
    }
    tox_options_free(opts);
    ck_assert_msg(relay != nullptr, "Failed to create TCP relay");

    IP_Port relay_ipport_tcp = {ip, net_htons(forwarder_tcp_relay_port)};

    uint8_t dpk[TOX_PUBLIC_KEY_SIZE];
    tox_self_get_dht_id(relay, dpk);

    printf("1-%d connected only to TCP server; %d-%d connected only to DHT\n",
           NUM_FORWARDER_TCP, NUM_FORWARDER_TCP + 1, NUM_FORWARDER);

    for (uint32_t i = 0; i < NUM_FORWARDER_TCP; ++i) {
        set_tcp_onion_status(nc_get_tcp_c(subtoxes[i]->c), 1);
        ck_assert_msg(add_tcp_relay(subtoxes[i]->c, &relay_ipport_tcp, dpk) == 0,
                      "Failed to add TCP relay");
    }

    IP_Port relay_ipport_udp = {ip, net_htons(tox_self_get_udp_port(relay, nullptr))};

    for (uint32_t i = NUM_FORWARDER_TCP; i < NUM_FORWARDER; ++i) {
        dht_bootstrap(subtoxes[i]->dht, &relay_ipport_udp, dpk);
    }

    printf("allowing DHT to populate\n");
    uint16_t dht_establish_iterations = NUM_FORWARDER * 5;

    for (uint32_t n = 0; n < NUM_FORWARDING_ITERATIONS; ++n) {
        for (uint32_t i = 0; i < NUM_FORWARDER; ++i) {
            test_data[i].sent = 0;
            test_data[i].returned = false;
        }

        do {
            for (uint32_t i = 0; i < NUM_FORWARDER; ++i) {
                Forwarding_Subtox *const subtox = subtoxes[i];
                mono_time_update(subtox->mono_time);
                networking_poll(subtox->net, &index[i]);
                do_net_crypto(subtox->c, &index[i]);
                do_dht(subtox->dht);

                if (dht_establish_iterations ||
                        test_data[i].returned ||
                        !mono_time_is_timeout(subtox->mono_time, test_data[i].sent, FORWARD_SEND_INTERVAL)) {
                    continue;
                }

                printf("%u", i + 1);

                if (i < NUM_FORWARDER_TCP) {
                    printf(" --> TCPRelay");
                }

                const uint16_t chain_length = i < NUM_FORWARDER_TCP ? i % 5 : i % 4 + 1;
                uint8_t chain_keys[4 * CRYPTO_PUBLIC_KEY_SIZE];

                uint32_t chain_i = NUM_FORWARDER_TCP + (random_u32(rng) % NUM_FORWARDER_DHT);
                const IP_Port first_ipp = {ip, net_htons(FORWARDING_BASE_PORT + chain_i)};

                printf(" --> %u", chain_i + 1);

                for (uint16_t j = 0; j < chain_length; ++j) {
                    // pick random different dht node:
                    chain_i += 1 + random_u32(rng) % (NUM_FORWARDER_DHT - 1);
                    chain_i = NUM_FORWARDER_TCP + (chain_i - NUM_FORWARDER_TCP) % NUM_FORWARDER_DHT;

                    const uint8_t *dest_pubkey = dht_get_self_public_key(subtoxes[chain_i]->dht);

                    memcpy(chain_keys + j * CRYPTO_PUBLIC_KEY_SIZE, dest_pubkey, CRYPTO_PUBLIC_KEY_SIZE);
                    printf(" --> %u", chain_i + 1);
                }

                printf("\n");

                const uint16_t length = 12;
                uint8_t data[12];

                memcpy(data, "hello:  ", 8);
                test_data[i].send_back = random_u32(rng);
                net_pack_u32(data + 8, test_data[i].send_back);

                if (i < NUM_FORWARDER_TCP) {
                    IP_Port tcp_forwarder;

                    if (!get_random_tcp_conn_ip_port(subtox->c, &tcp_forwarder)) {
                        continue;
                    }

                    if (send_tcp_forward_request(subtox->log, subtox->c, &tcp_forwarder, &first_ipp,
                                                 chain_keys, chain_length, data, length) == 0) {
                        test_data[i].sent = mono_time_get(subtox->mono_time);
                    }
                } else {
                    if (send_forward_request(subtox->net, &first_ipp,
                                             chain_keys, chain_length, data, length)) {
                        test_data[i].sent = mono_time_get(subtox->mono_time);
                    }
                }
            }

            tox_iterate(relay, nullptr);

            if (dht_establish_iterations) {
                --dht_establish_iterations;

                if (!dht_establish_iterations) {
                    printf("making forward requests and expecting replies\n");
                }
            }

            c_sleep(50);
        } while (!all_returned(test_data));

        // This doesn't really belong in this test.
        // It can be removed once the full announce client test is in place.
        printf("checking that nodes are marked as announce nodes\n");
        Node_format nodes[MAX_SENT_NODES];
        ck_assert(NUM_FORWARDER - NUM_FORWARDER_TCP > 1);

        for (uint32_t i = NUM_FORWARDER_TCP; i < NUM_FORWARDER; ++i) {
            ck_assert_msg(get_close_nodes(subtoxes[i]->dht, dht_get_self_public_key(subtoxes[i]->dht), nodes, net_family_unspec(), true,
                                          true) > 0,
                          "node %u has no nodes marked as announce nodes", i);
        }
    }

    for (uint32_t i = 0; i < NUM_FORWARDER; ++i) {
        kill_forwarding_subtox(mem, subtoxes[i]);
    }

    tox_kill(relay);
}

int main(void)
{
    setvbuf(stdout, nullptr, _IONBF, 0);

    test_forwarding();

    return 0;
}
