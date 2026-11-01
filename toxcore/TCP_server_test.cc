#include <gtest/gtest.h>

#include <chrono>
#include <thread>

#include "TCP_client.h"
#include "crypto_core.h"
#include "logger.h"
#include "mono_time.h"
#include "net.h"
#include "network.h"
#include "os_memory.h"
#include "os_network.h"
#include "os_random.h"
#include "tox.h"

namespace {

constexpr uint16_t kRelayPort = 33455;

void sleep_ms(int ms) { std::this_thread::sleep_for(std::chrono::milliseconds(ms)); }

// A relay must not read from a slot evicted earlier in the same epoll batch.
TEST(TCPServer, SurvivesSameKeyReconnectWithPendingData)
{
    Tox_Options *opts = tox_options_new(nullptr);
    ASSERT_NE(opts, nullptr);
    tox_options_set_udp_enabled(opts, false);
    tox_options_set_local_discovery_enabled(opts, false);
    tox_options_set_tcp_port(opts, kRelayPort);

    Tox_Err_New err;
    Tox *tox = tox_new(opts, &err);
    tox_options_free(opts);
    ASSERT_EQ(err, TOX_ERR_NEW_OK);
    ASSERT_NE(tox, nullptr);

    auto pump_relay = [&] { tox_iterate(tox, nullptr); };

    // Let the node settle, including its relay to itself (slot 0).
    for (int i = 0; i < 10; ++i) {
        pump_relay();
        sleep_ms(10);
    }

    uint8_t relay_pk[TOX_PUBLIC_KEY_SIZE];
    tox_self_get_dht_id(tox, relay_pk);

    const Random *rng = os_random();
    const Network *ns = os_network();
    const Memory *mem = os_memory();
    ASSERT_NE(rng, nullptr);
    ASSERT_NE(ns, nullptr);
    ASSERT_NE(mem, nullptr);

    Logger *logger = logger_new(mem);
    Mono_Time *mono_time = mono_time_new(mem, nullptr, nullptr);

    IP_Port relay;
    relay.ip.family = net_family_ipv4();
    relay.ip.ip.v4 = get_ip4_loopback();
    relay.port = net_htons(kRelayPort);

    auto confirm = [&](const uint8_t *pk, const uint8_t *sk) -> TCP_Client_Connection * {
        TCP_Client_Connection *c = new_tcp_connection(
            logger, mem, mono_time, rng, ns, &relay, relay_pk, pk, sk, nullptr, nullptr);
        sleep_ms(50);
        for (int i = 0; i < 30 && tcp_con_status(c) != TCP_CLIENT_CONFIRMED; ++i) {
            mono_time_update(mono_time);
            do_tcp_connection(logger, mono_time, c, nullptr);
            sleep_ms(10);
            pump_relay();
            sleep_ms(10);
        }
        return c;
    };

    // Shared by A and B.
    uint8_t key_pk[CRYPTO_PUBLIC_KEY_SIZE];
    uint8_t key_sk[CRYPTO_SECRET_KEY_SIZE];
    crypto_new_keypair(rng, key_pk, key_sk);

    uint8_t pk[CRYPTO_PUBLIC_KEY_SIZE];
    uint8_t sk[CRYPTO_SECRET_KEY_SIZE];

    // Slots are allocated from the top: put two above A, then free the top one so
    // B doesn't reuse A's slot.
    crypto_new_keypair(rng, pk, sk);
    TCP_Client_Connection *high = confirm(pk, sk);
    ASSERT_EQ(tcp_con_status(high), TCP_CLIENT_CONFIRMED);
    crypto_new_keypair(rng, pk, sk);
    TCP_Client_Connection *mid = confirm(pk, sk);
    ASSERT_EQ(tcp_con_status(mid), TCP_CLIENT_CONFIRMED);
    TCP_Client_Connection *a = confirm(key_pk, key_sk);
    ASSERT_EQ(tcp_con_status(a), TCP_CLIENT_CONFIRMED);

    kill_tcp_connection(high);
    for (int i = 0; i < 3; ++i) {
        pump_relay();
        sleep_ms(10);
    }

    // Confirm B without letting the relay handle its confirming packet yet.
    TCP_Client_Connection *b = new_tcp_connection(
        logger, mem, mono_time, rng, ns, &relay, relay_pk, key_pk, key_sk, nullptr, nullptr);
    ASSERT_NE(b, nullptr);
    sleep_ms(50);
    mono_time_update(mono_time);
    do_tcp_connection(logger, mono_time, b, nullptr);
    sleep_ms(20);
    pump_relay();
    sleep_ms(20);
    mono_time_update(mono_time);
    do_tcp_connection(logger, mono_time, b, nullptr);
    sleep_ms(20);
    ASSERT_EQ(tcp_con_status(b), TCP_CLIENT_CONFIRMED);

    // Queue a packet on A behind B's, in the same batch.
    ASSERT_EQ(send_routing_request(logger, a, relay_pk), 1);
    mono_time_update(mono_time);
    do_tcp_connection(logger, mono_time, a, nullptr);
    sleep_ms(20);

    // Confirming B evicts A's slot before A's packet is handled.
    pump_relay();
    sleep_ms(20);
    pump_relay();

    kill_tcp_connection(a);
    kill_tcp_connection(b);
    kill_tcp_connection(mid);
    logger_kill(logger);
    mono_time_free(mem, mono_time);
    tox_kill(tox);
}

}  // namespace
