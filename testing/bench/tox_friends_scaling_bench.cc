/* SPDX-License-Identifier: GPL-3.0-or-later
 * Copyright © 2026 The TokTok team.
 */

#include <benchmark/benchmark.h>

#include <cstddef>
#include <iostream>
#include <memory>
#include <vector>

#include "../../testing/support/public/simulation.hh"
#include "../../testing/support/public/tox_network.hh"
#include "../../toxcore/tox.h"

namespace {

using tox::test::ConnectedFriend;
using tox::test::setup_connected_friends;
using tox::test::SimulatedNode;
using tox::test::Simulation;

// --- Helper Contexts ---

struct GroupContext {
    uint32_t peer_count = 0;
    uint32_t group_number = UINT32_MAX;
};

// --- Fixtures ---

class ToxIterateScalingFixture : public benchmark::Fixture {
public:
    void SetUp(benchmark::State &state) override
    {
        // Explicitly clear members to handle fixture reuse or non-empty initial state.
        // Order matters: dependent objects first.
        friend_toxes.clear();
        friend_nodes.clear();
        main_tox.reset();
        main_node.reset();
        sim.reset();

        int num_friends = state.range(0);
        sim = std::make_unique<Simulation>(12345);
        main_node = sim->create_node();
        main_tox = main_node->create_tox();

        for (int i = 0; i < num_friends; ++i) {
            auto node = sim->create_node();
            auto tox = node->create_tox();

            uint8_t friend_pk[TOX_PUBLIC_KEY_SIZE];
            tox_self_get_public_key(tox.get(), friend_pk);

            Tox_Err_Friend_Add err;
            tox_friend_add_norequest(main_tox.get(), friend_pk, &err);

            friend_nodes.push_back(std::move(node));
            friend_toxes.push_back(std::move(tox));
        }
    }

protected:
    std::unique_ptr<Simulation> sim;
    std::unique_ptr<SimulatedNode> main_node;
    SimulatedNode::ToxPtr main_tox;
    std::vector<std::unique_ptr<SimulatedNode>> friend_nodes;
    std::vector<SimulatedNode::ToxPtr> friend_toxes;
};

// --- Contexts for Shared State Benchmarks ---

class ToxOnlineDisconnectedScalingFixture : public benchmark::Fixture {
    static constexpr bool kVerbose = false;

public:
    void SetUp(benchmark::State &state) override
    {
        // Explicitly clear members to handle fixture reuse or non-empty initial state.
        // Order matters: dependent objects first (Tox depends on Node).
        main_tox.reset();
        bootstrap_tox.reset();
        main_node.reset();
        bootstrap_node.reset();
        sim.reset();

        int num_friends = state.range(0);
        sim = std::make_unique<Simulation>(12345);
        sim->net().set_latency(1);  // Low latency to encourage traffic
        sim->net().set_verbose(kVerbose);

        // Create a bootstrap node to ensure we are "online" on the DHT
        bootstrap_node = sim->create_node();

        auto log_cb = [](Tox *tox, Tox_Log_Level level, const char *file, uint32_t line,
                          const char *func, const char *message, void *user_data) {
            if (kVerbose) {
                std::cerr << "Log: " << file << ":" << line << " (" << func << ") " << message
                          << std::endl;
            }
        };

        auto opts_bs = std::unique_ptr<Tox_Options, decltype(&tox_options_free)>(
            tox_options_new(nullptr), tox_options_free);
        assert(opts_bs);
        tox_options_set_local_discovery_enabled(opts_bs.get(), false);
        tox_options_set_ipv6_enabled(opts_bs.get(), false);
        tox_options_set_log_callback(opts_bs.get(), log_cb);

        bootstrap_tox = bootstrap_node->create_tox(opts_bs.get());
        uint8_t bootstrap_pk[TOX_PUBLIC_KEY_SIZE];
        tox_self_get_dht_id(bootstrap_tox.get(), bootstrap_pk);
        uint16_t bootstrap_port = bootstrap_node->get_primary_socket()->local_port();

        main_node = sim->create_node();
        auto opts = std::unique_ptr<Tox_Options, decltype(&tox_options_free)>(
            tox_options_new(nullptr), tox_options_free);
        assert(opts);

        // Disable local discovery to force DHT usage
        tox_options_set_local_discovery_enabled(opts.get(), false);
        tox_options_set_ipv6_enabled(opts.get(), false);
        tox_options_set_log_callback(opts.get(), log_cb);
        main_tox = main_node->create_tox(opts.get());

        // Bootstrap to the network (Mutual bootstrap to ensure connectivity)
        Ip_Ntoa bs_ip_str_buf;
        const char *bs_ip_str = net_ip_ntoa(&bootstrap_node->ip, &bs_ip_str_buf);

        Tox_Err_Bootstrap bs_err;
        tox_bootstrap(main_tox.get(), bs_ip_str, bootstrap_port, bootstrap_pk, &bs_err);
        if (bs_err != TOX_ERR_BOOTSTRAP_OK) {
            std::cerr << "bootstrapping failed: " << bs_err << "\n";
            std::abort();
        }

        // Run until we are connected to the DHT
        sim->run_until(
            [&]() {
                tox_iterate(main_tox.get(), nullptr);
                tox_iterate(bootstrap_tox.get(), nullptr);
                return tox_self_get_connection_status(main_tox.get()) != TOX_CONNECTION_NONE;
            },
            15000);

        if (tox_self_get_connection_status(main_tox.get()) == TOX_CONNECTION_NONE) {
            std::cerr << "WARNING: Failed to connect to DHT in SetUp (timeout 30s)\n";
            std::abort();
        }

        for (int i = 0; i < num_friends; ++i) {
            // Add friend but don't create a node for them -> they are offline
            uint8_t friend_pk[TOX_PUBLIC_KEY_SIZE];
            // Just generate a random PK
            main_node->fake_random().bytes(friend_pk, TOX_PUBLIC_KEY_SIZE);

            Tox_Err_Friend_Add err;
            tox_friend_add_norequest(main_tox.get(), friend_pk, &err);
        }
    }

protected:
    std::unique_ptr<Simulation> sim;
    std::unique_ptr<SimulatedNode> main_node;
    SimulatedNode::ToxPtr main_tox;
    std::unique_ptr<SimulatedNode> bootstrap_node;
    SimulatedNode::ToxPtr bootstrap_tox;
};

BENCHMARK_DEFINE_F(ToxOnlineDisconnectedScalingFixture, Iterate)(benchmark::State &state)
{
    if (tox_self_get_connection_status(main_tox.get()) == TOX_CONNECTION_NONE) {
        state.SkipWithError("not connected to DHT");
    }

    for (auto _ : state) {
        tox_iterate(main_tox.get(), nullptr);
        tox_iterate(bootstrap_tox.get(), nullptr);

        uint32_t interval = tox_iteration_interval(main_tox.get());
        uint32_t interval_bs = tox_iteration_interval(bootstrap_tox.get());
        sim->advance_time(std::min(interval, interval_bs));
    }

    state.counters["mem_current"]
        = benchmark::Counter(static_cast<double>(main_node->fake_memory().current_allocation()),
            benchmark::Counter::kDefaults, benchmark::Counter::OneK::kIs1024);
}
BENCHMARK_REGISTER_F(ToxOnlineDisconnectedScalingFixture, Iterate)
    ->Arg(0)
    ->Arg(10)
    ->Arg(100)
    ->Arg(1000)
    ->Arg(2000);

struct ConnectedContext {
    std::unique_ptr<Simulation> sim;
    std::unique_ptr<SimulatedNode> main_node;
    SimulatedNode::ToxPtr main_tox;
    std::vector<ConnectedFriend> friends;
    int num_friends = -1;

    void Setup(int n)
    {
        if (num_friends == n)
            return;

        // Destruction order is critical
        friends.clear();
        main_tox.reset();
        main_node.reset();
        sim.reset();

        sim = std::make_unique<Simulation>(12345);
        sim->net().set_latency(5);
        main_node = sim->create_node();
        main_tox = main_node->create_tox();

        num_friends = n;
        if (n > 0) {
            friends = setup_connected_friends(*sim, main_tox.get(), *main_node, num_friends);
        }
    }

    ~ConnectedContext();
};

ConnectedContext::~ConnectedContext() = default;

struct GroupScalingContext {
    static constexpr bool verbose = false;

    std::unique_ptr<Simulation> sim;
    std::unique_ptr<SimulatedNode> main_node;
    SimulatedNode::ToxPtr main_tox;
    GroupContext main_ctx;
    std::vector<ConnectedFriend> friends;
    int num_peers = -1;

    void Setup(int peers)
    {
        if (num_peers == peers)
            return;

        // Destruction order is critical
        friends.clear();
        main_ctx = GroupContext();
        main_tox.reset();
        main_node.reset();
        sim.reset();

        sim = std::make_unique<Simulation>(12345);
        sim->net().set_latency(5);
        main_node = sim->create_node();

        auto opts = std::unique_ptr<Tox_Options, decltype(&tox_options_free)>(
            tox_options_new(nullptr), tox_options_free);
        tox_options_set_ipv6_enabled(opts.get(), false);
        tox_options_set_local_discovery_enabled(opts.get(), false);
        main_tox = main_node->create_tox(opts.get());

        num_peers = peers;

        // Setup Group Callbacks
        tox_callback_group_peer_join(
            main_tox.get(), [](Tox *, uint32_t, uint32_t, void *user_data) {
                static_cast<GroupContext *>(user_data)->peer_count++;
            });
        tox_callback_group_peer_exit(main_tox.get(),
            [](Tox *, uint32_t, uint32_t, Tox_Group_Exit_Type, const uint8_t *, std::size_t,
                const uint8_t *, std::size_t,
                void *user_data) { static_cast<GroupContext *>(user_data)->peer_count--; });

        Tox_Err_Group_New err_new;
        main_ctx.group_number = tox_group_new(main_tox.get(), TOX_GROUP_PRIVACY_STATE_PUBLIC,
            reinterpret_cast<const uint8_t *>("test"), 4, reinterpret_cast<const uint8_t *>("main"),
            4, &err_new);

        if (num_peers > 0) {
            // Setup Friends
            auto opts_friends = std::unique_ptr<Tox_Options, decltype(&tox_options_free)>(
                tox_options_new(nullptr), tox_options_free);
            tox_options_set_ipv6_enabled(opts_friends.get(), false);
            tox_options_set_local_discovery_enabled(opts_friends.get(), false);

            friends = setup_connected_friends(
                *sim, main_tox.get(), *main_node, num_peers, opts_friends.get());

            // Invite Friends
            for (const auto &f : friends) {
                tox_group_invite_friend(
                    main_tox.get(), main_ctx.group_number, f.friend_number, nullptr);
            }

            // Wait for Joins
            std::vector<uint32_t> peer_group_numbers(num_peers, UINT32_MAX);
            sim->run_until(
                [&]() {
                    tox_iterate(main_tox.get(), &main_ctx);

                    // Poll events
                    for (std::size_t i = 0; i < friends.size(); ++i) {
                        auto batches = friends[i].runner->poll_events();
                        for (const auto &batch : batches) {
                            std::size_t size = tox_events_get_size(batch.get());
                            for (std::size_t k = 0; k < size; ++k) {
                                const Tox_Event *e = tox_events_get(batch.get(), k);
                                if (tox_event_get_type(e) == TOX_EVENT_GROUP_INVITE) {
                                    auto *ev = tox_event_get_group_invite(e);
                                    uint32_t friend_number
                                        = tox_event_group_invite_get_friend_number(ev);
                                    const uint8_t *data
                                        = tox_event_group_invite_get_invite_data(ev);
                                    std::size_t len
                                        = tox_event_group_invite_get_invite_data_length(ev);
                                    std::vector<uint8_t> invite_data(data, data + len);
                                    friends[i].runner->execute([=](Tox *tox) {
                                        tox_group_invite_accept(tox, friend_number,
                                            invite_data.data(), invite_data.size(),
                                            reinterpret_cast<const uint8_t *>("peer"), 4, nullptr,
                                            0, nullptr);
                                    });
                                } else if (tox_event_get_type(e) == TOX_EVENT_GROUP_SELF_JOIN) {
                                    auto *ev = tox_event_get_group_self_join(e);
                                    peer_group_numbers[i]
                                        = tox_event_group_self_join_get_group_number(ev);
                                }
                            }
                        }
                    }

                    bool all_joined = true;
                    for (auto gn : peer_group_numbers)
                        if (gn == UINT32_MAX)
                            all_joined = false;
                    return all_joined;
                },
                60000);

            // Wait for Convergence
            sim->run_until(
                [&]() {
                    tox_iterate(main_tox.get(), &main_ctx);
                    if (main_ctx.peer_count >= static_cast<uint32_t>(num_peers))
                        return true;

                    static uint64_t last_print = 0;
                    if (verbose && sim->clock().current_time_ms() - last_print > 1000) {
                        std::cerr << "Peers joined: " << main_ctx.peer_count << "/" << num_peers
                                  << std::endl;
                        last_print = sim->clock().current_time_ms();
                    }
                    return false;
                },
                120000);
        }
    }

    ~GroupScalingContext();
};

GroupScalingContext::~GroupScalingContext() = default;

// --- Benchmark Definitions ---

BENCHMARK_DEFINE_F(ToxIterateScalingFixture, Iterate)(benchmark::State &state)
{
    for (auto _ : state) {
        tox_iterate(main_tox.get(), nullptr);
    }

    state.counters["mem_current"]
        = benchmark::Counter(static_cast<double>(main_node->fake_memory().current_allocation()),
            benchmark::Counter::kDefaults, benchmark::Counter::OneK::kIs1024);
    state.counters["mem_max"]
        = benchmark::Counter(static_cast<double>(main_node->fake_memory().max_allocation()),
            benchmark::Counter::kDefaults, benchmark::Counter::OneK::kIs1024);
}
BENCHMARK_REGISTER_F(ToxIterateScalingFixture, Iterate)
    ->Arg(0)
    ->Arg(10)
    ->Arg(100)
    ->Arg(200)
    ->Arg(300);

void RunConnectedScaling(benchmark::State &state, ConnectedContext &ctx)
{
    ctx.Setup(state.range(0));

    for (auto _ : state) {
        tox_iterate(ctx.main_tox.get(), nullptr);
    }

    state.counters["mem_current"]
        = benchmark::Counter(static_cast<double>(ctx.main_node->fake_memory().current_allocation()),
            benchmark::Counter::kDefaults, benchmark::Counter::OneK::kIs1024);
    state.counters["mem_max"]
        = benchmark::Counter(static_cast<double>(ctx.main_node->fake_memory().max_allocation()),
            benchmark::Counter::kDefaults, benchmark::Counter::OneK::kIs1024);
}

void RunGroupScaling(benchmark::State &state, GroupScalingContext &ctx)
{
    ctx.Setup(state.range(0));

    for (auto _ : state) {
        tox_iterate(ctx.main_tox.get(), &ctx.main_ctx);
    }

    state.counters["mem_current"]
        = benchmark::Counter(static_cast<double>(ctx.main_node->fake_memory().current_allocation()),
            benchmark::Counter::kDefaults, benchmark::Counter::OneK::kIs1024);
    state.counters["mem_max"]
        = benchmark::Counter(static_cast<double>(ctx.main_node->fake_memory().max_allocation()),
            benchmark::Counter::kDefaults, benchmark::Counter::OneK::kIs1024);
    state.counters["peers"] = benchmark::Counter(
        static_cast<double>(ctx.main_ctx.peer_count + 1), benchmark::Counter::kDefaults);
}

/**
 * @brief Benchmark the time and CPU required to discover and connect to many friends.
 *
 * This stresses the Onion Client's discovery mechanism (shared key caching)
 * and the DHT's shared key cache efficiency.
 */
static void BM_MassDiscovery(benchmark::State &state)
{
    const int num_friends = state.range(0);

    for (auto _ : state) {
        Simulation sim{12345};
        // Set a realistic latency to ensure packets are in flight and DHT/Onion logic
        // has to run multiple iterations.
        sim.net().set_latency(10);

        auto alice_node = sim.create_node();
        auto alice_tox = alice_node->create_tox();

        // setup_connected_friends runs the simulation until all friends are connected.
        auto friends = setup_connected_friends(sim, alice_tox.get(), *alice_node, num_friends);

        benchmark::DoNotOptimize(friends);
    }
}
BENCHMARK(BM_MassDiscovery)
    ->Arg(50)
    ->Arg(100)
    ->Arg(200)
    ->Unit(benchmark::kMillisecond)
    ->Iterations(5);

}  // namespace

int main(int argc, char **argv)
{
    ::benchmark::Initialize(&argc, argv);
    if (::benchmark::ReportUnrecognizedArguments(argc, argv)) {
        return 1;
    }

    ConnectedContext connected_ctx;
    benchmark::RegisterBenchmark("ToxConnectedScalingFixture/IterateConnected",
        [&](benchmark::State &st) { RunConnectedScaling(st, connected_ctx); })
        ->Arg(0)
        ->Arg(10)
        ->Arg(20)
        ->Arg(50);

    GroupScalingContext group_ctx;
    benchmark::RegisterBenchmark("ToxGroupScalingFixture/IterateGroup",
        [&](benchmark::State &st) { RunGroupScaling(st, group_ctx); })
        ->Arg(0)
        ->Arg(10)
        ->Arg(20)
        ->Arg(50);

    ::benchmark::RunSpecifiedBenchmarks();
    ::benchmark::Shutdown();
    return 0;
}
