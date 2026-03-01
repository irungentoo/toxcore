/* SPDX-License-Identifier: GPL-3.0-or-later
 * Copyright © 2026 The TokTok team.
 */

#include <benchmark/benchmark.h>

#include <cstddef>
#include <iostream>

#include "../../testing/support/public/simulation.hh"
#include "../../toxcore/network.h"
#include "../../toxcore/tox.h"

namespace {

using tox::test::Simulation;

struct Context {
    std::size_t count = 0;
};

void BM_ToxMessengerThroughput(benchmark::State &state)
{
    Simulation sim{12345};
    sim.net().set_latency(5);
    auto node1 = sim.create_node();
    auto node2 = sim.create_node();

    auto opts1 = std::unique_ptr<Tox_Options, decltype(&tox_options_free)>(
        tox_options_new(nullptr), tox_options_free);
    tox_options_set_log_user_data(opts1.get(), const_cast<char *>("Tox1"));
    tox_options_set_ipv6_enabled(opts1.get(), false);
    tox_options_set_local_discovery_enabled(opts1.get(), false);

    auto opts2 = std::unique_ptr<Tox_Options, decltype(&tox_options_free)>(
        tox_options_new(nullptr), tox_options_free);
    tox_options_set_log_user_data(opts2.get(), const_cast<char *>("Tox2"));
    tox_options_set_ipv6_enabled(opts2.get(), false);
    tox_options_set_local_discovery_enabled(opts2.get(), false);

    auto tox1 = node1->create_tox(opts1.get());
    auto tox2 = node2->create_tox(opts2.get());

    if (!tox1 || !tox2) {
        state.SkipWithError("Failed to create Tox instances");
        return;
    }

    uint8_t tox1_pk[TOX_PUBLIC_KEY_SIZE];
    tox_self_get_public_key(tox1.get(), tox1_pk);
    uint8_t tox2_pk[TOX_PUBLIC_KEY_SIZE];
    tox_self_get_public_key(tox2.get(), tox2_pk);

    uint8_t tox1_dht_id[TOX_PUBLIC_KEY_SIZE];
    tox_self_get_dht_id(tox1.get(), tox1_dht_id);
    uint8_t tox2_dht_id[TOX_PUBLIC_KEY_SIZE];
    tox_self_get_dht_id(tox2.get(), tox2_dht_id);

    Tox_Err_Friend_Add friend_add_err;
    uint32_t f1 = tox_friend_add_norequest(tox1.get(), tox2_pk, &friend_add_err);
    uint32_t f2 = tox_friend_add_norequest(tox2.get(), tox1_pk, &friend_add_err);

    uint16_t port1 = node1->get_primary_socket()->local_port();
    uint16_t port2 = node2->get_primary_socket()->local_port();

    char ip1[TOX_INET6_ADDRSTRLEN];
    ip_parse_addr(&node1->ip, ip1, sizeof(ip1));
    char ip2[TOX_INET6_ADDRSTRLEN];
    ip_parse_addr(&node2->ip, ip2, sizeof(ip2));

    tox_bootstrap(tox2.get(), ip1, port1, tox1_dht_id, nullptr);
    tox_bootstrap(tox1.get(), ip2, port2, tox2_dht_id, nullptr);

    bool connected = false;
    sim.run_until(
        [&]() {
            tox_iterate(tox1.get(), nullptr);
            tox_iterate(tox2.get(), nullptr);
            sim.advance_time(90);  // +10ms from run_until = 100ms
            connected
                = (tox_friend_get_connection_status(tox1.get(), f1, nullptr) != TOX_CONNECTION_NONE
                    && tox_friend_get_connection_status(tox2.get(), f2, nullptr)
                        != TOX_CONNECTION_NONE);
            return connected;
        },
        60000);

    if (!connected) {
        state.SkipWithError("Failed to connect toxes within 60s");
        return;
    }

    const uint8_t msg[] = "benchmark message";
    const std::size_t msg_len = sizeof(msg);

    Context ctx;
    tox_callback_friend_message(tox2.get(),
        [](Tox *, uint32_t, Tox_Message_Type, const uint8_t *, std::size_t, void *user_data) {
            static_cast<Context *>(user_data)->count++;
        });

    for (auto _ : state) {
        tox_friend_send_message(tox1.get(), f1, TOX_MESSAGE_TYPE_NORMAL, msg, msg_len, nullptr);

        for (int i = 0; i < 5; ++i) {
            sim.advance_time(1);
            tox_iterate(tox1.get(), nullptr);
            tox_iterate(tox2.get(), &ctx);
        }
    }

    state.counters["messages_received"]
        = benchmark::Counter(static_cast<double>(ctx.count), benchmark::Counter::kAvgThreads);
}

BENCHMARK(BM_ToxMessengerThroughput);

void BM_ToxMessengerBidirectional(benchmark::State &state)
{
    Simulation sim{12345};
    sim.net().set_latency(5);
    auto node1 = sim.create_node();
    auto node2 = sim.create_node();

    auto opts1 = std::unique_ptr<Tox_Options, decltype(&tox_options_free)>(
        tox_options_new(nullptr), tox_options_free);
    tox_options_set_log_user_data(opts1.get(), const_cast<char *>("Tox1"));
    tox_options_set_ipv6_enabled(opts1.get(), false);
    tox_options_set_local_discovery_enabled(opts1.get(), false);

    auto opts2 = std::unique_ptr<Tox_Options, decltype(&tox_options_free)>(
        tox_options_new(nullptr), tox_options_free);
    tox_options_set_log_user_data(opts2.get(), const_cast<char *>("Tox2"));
    tox_options_set_ipv6_enabled(opts2.get(), false);
    tox_options_set_local_discovery_enabled(opts2.get(), false);

    auto tox1 = node1->create_tox(opts1.get());
    auto tox2 = node2->create_tox(opts2.get());

    if (!tox1 || !tox2) {
        state.SkipWithError("Failed to create Tox instances");
        return;
    }

    uint8_t tox1_pk[TOX_PUBLIC_KEY_SIZE];
    tox_self_get_public_key(tox1.get(), tox1_pk);
    uint8_t tox2_pk[TOX_PUBLIC_KEY_SIZE];
    tox_self_get_public_key(tox2.get(), tox2_pk);

    uint8_t tox1_dht_id[TOX_PUBLIC_KEY_SIZE];
    tox_self_get_dht_id(tox1.get(), tox1_dht_id);
    uint8_t tox2_dht_id[TOX_PUBLIC_KEY_SIZE];
    tox_self_get_dht_id(tox2.get(), tox2_dht_id);

    Tox_Err_Friend_Add friend_add_err;
    uint32_t f1 = tox_friend_add_norequest(tox1.get(), tox2_pk, &friend_add_err);
    uint32_t f2 = tox_friend_add_norequest(tox2.get(), tox1_pk, &friend_add_err);

    uint16_t port1 = node1->get_primary_socket()->local_port();
    uint16_t port2 = node2->get_primary_socket()->local_port();

    char ip1[TOX_INET6_ADDRSTRLEN];
    ip_parse_addr(&node1->ip, ip1, sizeof(ip1));
    char ip2[TOX_INET6_ADDRSTRLEN];
    ip_parse_addr(&node2->ip, ip2, sizeof(ip2));

    tox_bootstrap(tox2.get(), ip1, port1, tox1_dht_id, nullptr);
    tox_bootstrap(tox1.get(), ip2, port2, tox2_dht_id, nullptr);

    bool connected = false;
    sim.run_until(
        [&]() {
            tox_iterate(tox1.get(), nullptr);
            tox_iterate(tox2.get(), nullptr);
            sim.advance_time(90);  // +10ms from run_until = 100ms
            connected
                = (tox_friend_get_connection_status(tox1.get(), f1, nullptr) != TOX_CONNECTION_NONE
                    && tox_friend_get_connection_status(tox2.get(), f2, nullptr)
                        != TOX_CONNECTION_NONE);
            return connected;
        },
        60000);

    if (!connected) {
        state.SkipWithError("Failed to connect toxes within 60s");
        return;
    }

    const uint8_t msg[] = "benchmark message";
    const std::size_t msg_len = sizeof(msg);

    Context ctx1, ctx2;
    tox_callback_friend_message(tox1.get(),
        [](Tox *, uint32_t, Tox_Message_Type, const uint8_t *, std::size_t, void *user_data) {
            static_cast<Context *>(user_data)->count++;
        });

    tox_callback_friend_message(tox2.get(),
        [](Tox *, uint32_t, Tox_Message_Type, const uint8_t *, std::size_t, void *user_data) {
            static_cast<Context *>(user_data)->count++;
        });

    for (auto _ : state) {
        tox_friend_send_message(tox1.get(), f1, TOX_MESSAGE_TYPE_NORMAL, msg, msg_len, nullptr);
        tox_friend_send_message(tox2.get(), f2, TOX_MESSAGE_TYPE_NORMAL, msg, msg_len, nullptr);

        for (int i = 0; i < 5; ++i) {
            sim.advance_time(1);
            tox_iterate(tox1.get(), &ctx1);
            tox_iterate(tox2.get(), &ctx2);
        }
    }

    state.counters["messages_received"] = benchmark::Counter(
        static_cast<double>(ctx1.count + ctx2.count), benchmark::Counter::kAvgThreads);
}

BENCHMARK(BM_ToxMessengerBidirectional);

}  // namespace

BENCHMARK_MAIN();
