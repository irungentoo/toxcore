/* SPDX-License-Identifier: GPL-3.0-or-later
 * Copyright © 2026 The TokTok team.
 */

#include "public/tox_network.hh"

#include <gtest/gtest.h>

#include <atomic>
#include <cstddef>
#include <iomanip>
#include <sstream>

#include "../../toxcore/attributes.h"
#include "../../toxcore/network.h"

namespace tox::test {
namespace {

    TEST(ToxNetworkTest, SetupConnectedFriends)
    {
        Simulation sim{12345};
        sim.net().set_latency(5);
        auto main_node = sim.create_node();
        auto main_tox = main_node->create_tox();
        ASSERT_NE(main_tox, nullptr);

        const int num_friends = 3;
        auto friends = setup_connected_friends(sim, main_tox.get(), *main_node, num_friends);

        ASSERT_EQ(friends.size(), num_friends);

        // Verification of connection status is done inside setup_connected_friends now,
        // but we can double check main_tox's view.
        for (const auto &f : friends) {
            EXPECT_NE(tox_friend_get_connection_status(main_tox.get(), f.friend_number, nullptr),
                TOX_CONNECTION_NONE);
        }

        // Verify they can actually communicate
        struct Context {
            std::atomic<int> count{0};
        } ctx;

        tox_callback_friend_message(main_tox.get(),
            [](Tox *_Nonnull, uint32_t, Tox_Message_Type, const uint8_t *_Nonnull, std::size_t,
                void *_Nullable user_data) { static_cast<Context *>(user_data)->count++; });

        for (const auto &f : friends) {
            f.runner->execute([](Tox *tox) {
                const uint8_t msg[] = "hello";
                tox_friend_send_message(tox, 0, TOX_MESSAGE_TYPE_NORMAL, msg, sizeof(msg), nullptr);
            });
        }

        sim.run_until([&]() {
            tox_iterate(main_tox.get(), &ctx);
            return ctx.count == num_friends;
        });

        EXPECT_EQ(ctx.count, num_friends);
    }

    TEST(ToxNetworkTest, Setup50ConnectedFriends)
    {
        Simulation sim{12345};
        sim.net().set_latency(5);
        auto main_node = sim.create_node();
        auto main_tox = main_node->create_tox();
        ASSERT_NE(main_tox, nullptr);

        const int num_friends = 50;
        auto friends = setup_connected_friends(sim, main_tox.get(), *main_node, num_friends);

        ASSERT_EQ(friends.size(), num_friends);

        struct Context {
            std::atomic<int> count{0};
        } ctx;

        tox_callback_friend_message(main_tox.get(),
            [](Tox *_Nonnull, uint32_t, Tox_Message_Type, const uint8_t *_Nonnull, std::size_t,
                void *_Nullable user_data) { static_cast<Context *>(user_data)->count++; });

        for (const auto &f : friends) {
            f.runner->execute([](Tox *tox) {
                const uint8_t msg[] = "hello";
                tox_friend_send_message(tox, 0, TOX_MESSAGE_TYPE_NORMAL, msg, sizeof(msg), nullptr);
            });
        }

        sim.run_until(
            [&]() {
                tox_iterate(main_tox.get(), &ctx);
                return ctx.count == num_friends;
            },
            60000);

        EXPECT_EQ(ctx.count, num_friends);
    }

    TEST(ToxNetworkTest, ConnectFriends)
    {
        Simulation sim{12345};
        sim.net().set_latency(5);
        auto node1 = sim.create_node();
        auto tox1 = node1->create_tox();
        auto node2 = sim.create_node();
        auto tox2 = node2->create_tox();

        ASSERT_NE(tox1, nullptr);
        ASSERT_NE(tox2, nullptr);

        ASSERT_TRUE(connect_friends(sim, *node1, tox1.get(), *node2, tox2.get()));

        EXPECT_NE(tox_friend_get_connection_status(tox1.get(), 0, nullptr), TOX_CONNECTION_NONE);
        EXPECT_NE(tox_friend_get_connection_status(tox2.get(), 0, nullptr), TOX_CONNECTION_NONE);

        // Verify communication
        std::atomic<bool> received{false};
        tox_callback_friend_message(tox2.get(),
            [](Tox *_Nonnull, uint32_t, Tox_Message_Type, const uint8_t *_Nonnull, std::size_t,
                void *_Nullable user_data) {
                *static_cast<std::atomic<bool> *>(user_data) = true;
            });

        const uint8_t msg[] = "hello";
        tox_friend_send_message(tox1.get(), 0, TOX_MESSAGE_TYPE_NORMAL, msg, sizeof(msg), nullptr);

        sim.run_until([&]() {
            tox_iterate(tox1.get(), nullptr);
            tox_iterate(tox2.get(), &received);
            return received.load();
        });

        EXPECT_TRUE(received);
    }

    TEST(ToxNetworkTest, SetupConnectedGroup)
    {
        Simulation sim{12345};
        sim.net().set_latency(5);
        auto main_node = sim.create_node();
        auto main_tox = main_node->create_tox();
        ASSERT_NE(main_tox, nullptr);

        const int num_friends = 15;
        auto friends = setup_connected_friends(sim, main_tox.get(), *main_node, num_friends);
        ASSERT_EQ(friends.size(), num_friends);

        uint32_t group_number = setup_connected_group(sim, main_tox.get(), friends);
        EXPECT_NE(group_number, UINT32_MAX);

        // Verify we can send a group message
        struct Context {
            std::atomic<int> count{0};
        } ctx;

        tox_callback_group_message(main_tox.get(),
            [](Tox *_Nonnull, uint32_t, uint32_t, Tox_Message_Type, const uint8_t *_Nonnull,
                std::size_t, uint32_t,
                void *_Nullable user_data) { static_cast<Context *>(user_data)->count++; });

        for (const auto &f : friends) {
            f.runner->execute([](Tox *tox) {
                const uint8_t msg[] = "hello";
                uint32_t f_gn = 0;  // First group
                Tox_Err_Group_Send_Message err_send;
                tox_group_send_message(
                    tox, f_gn, TOX_MESSAGE_TYPE_NORMAL, msg, sizeof(msg), &err_send);
            });
        }

        sim.run_until(
            [&]() {
                tox_iterate(main_tox.get(), &ctx);
                return ctx.count == num_friends;
            },
            10000);

        EXPECT_EQ(ctx.count, num_friends);
    }

    TEST(ToxNetworkTest, Setup50ConnectedGroup)
    {
        Simulation sim{12345};
        sim.net().set_latency(5);
        auto main_node = sim.create_node();
        auto main_tox = main_node->create_tox();
        ASSERT_NE(main_tox, nullptr);

        const int num_friends = 50;
        auto friends = setup_connected_friends(sim, main_tox.get(), *main_node, num_friends);
        ASSERT_EQ(friends.size(), num_friends);

        uint32_t group_number = setup_connected_group(sim, main_tox.get(), friends);
        EXPECT_NE(group_number, UINT32_MAX);

        struct Context {
            std::atomic<int> count{0};
        } ctx;

        tox_callback_group_message(main_tox.get(),
            [](Tox *_Nonnull, uint32_t, uint32_t, Tox_Message_Type, const uint8_t *_Nonnull,
                std::size_t, uint32_t,
                void *_Nullable user_data) { static_cast<Context *>(user_data)->count++; });

        for (const auto &f : friends) {
            f.runner->execute([](Tox *tox) {
                const uint8_t msg[] = "hello";
                uint32_t f_gn = 0;
                Tox_Err_Group_Send_Message err_send;
                tox_group_send_message(
                    tox, f_gn, TOX_MESSAGE_TYPE_NORMAL, msg, sizeof(msg), &err_send);
            });
        }

        sim.run_until(
            [&]() {
                tox_iterate(main_tox.get(), &ctx);
                return ctx.count == num_friends;
            },
            120000);

        EXPECT_EQ(ctx.count, num_friends);
    }

    TEST(ToxNetworkTest, TcpRelayChaining)
    {
        constexpr bool kDebug = false;

        Simulation sim{0};
        sim.net().set_verbose(false);

        if (kDebug) {
            using namespace log_filter;
            sim.set_log_filter(level(TOX_LOG_LEVEL_DEBUG)
                || (level(TOX_LOG_LEVEL_TRACE)
                    && (file("TCP") || file("onion.c") || func("dht_isconnected"))
                    && !message("not sending repeated announce request")));
        }

        struct ToxOptionsDeleter {
            void operator()(Tox_Options *opts) { tox_options_free(opts); }
        };
        std::unique_ptr<Tox_Options, ToxOptionsDeleter> opts(tox_options_new(nullptr));
        tox_options_set_udp_enabled(opts.get(), false);
        tox_options_set_ipv6_enabled(opts.get(), false);
        tox_options_set_local_discovery_enabled(opts.get(), false);

        auto create = [&](const char *name, uint16_t port, bool udp_enabled = false) {
            tox_options_set_tcp_port(opts.get(), port);
            if (udp_enabled) {
                tox_options_set_start_port(opts.get(), port);
                tox_options_set_end_port(opts.get(), port);
            }
            tox_options_set_udp_enabled(opts.get(), udp_enabled);
            auto node = sim.create_node();
            auto tox = node->create_tox(opts.get());
            if (!tox) {
                std::cerr << "Failed to create node " << name << " on port " << port << std::endl;
                std::abort();
            }
            return std::make_pair(std::move(node), std::move(tox));
        };

        // Servers (Enable UDP for relays so they can talk to each other)
        auto [nodeA, toxA] = create("A", 20001, true);
        auto [nodeB, toxB] = create("B", 20002, true);

        // Clients
        auto [nodeC, toxC] = create("C", 0);
        auto [nodeD, toxD] = create("D", 0);
        auto [nodeE, toxE] = create("E", 0);
        auto [nodeF, toxF] = create("F", 0);

        auto get_info = [](SimulatedNode &node, Tox *tox) {
            uint8_t pk[TOX_PUBLIC_KEY_SIZE];
            tox_self_get_public_key(tox, pk);
            uint8_t dht_id[TOX_PUBLIC_KEY_SIZE];
            tox_self_get_dht_id(tox, dht_id);

            char ip[TOX_INET_ADDRSTRLEN];
            ip_parse_addr(&node.ip, ip, sizeof(ip));
            uint16_t port = tox_self_get_tcp_port(tox, nullptr);
            if (kDebug) {
                std::cout << "Node Info: IP=" << ip << " Port=" << port << std::endl;

                auto to_hex = [](const uint8_t *data) {
                    std::stringstream ss;
                    ss << std::hex << std::setfill('0');
                    for (int i = 0; i < TOX_PUBLIC_KEY_SIZE; ++i)
                        ss << std::setw(2) << static_cast<int>(data[i]);
                    return ss.str();
                };

                std::cout << "PK:     " << to_hex(pk) << std::endl;
                std::cout << "DHT ID: " << to_hex(dht_id) << std::endl;
            }

            return std::make_tuple(std::vector<uint8_t>(pk, pk + TOX_PUBLIC_KEY_SIZE),
                std::vector<uint8_t>(dht_id, dht_id + TOX_PUBLIC_KEY_SIZE), std::string(ip), port);
        };

        auto [pkA, dhtIdA, ipA, portA] = get_info(*nodeA, toxA.get());
        auto [pkB, dhtIdB, ipB, portB] = get_info(*nodeB, toxB.get());

        // Helper to connect to a relay (bootstrap + add_tcp_relay)
        auto connect_to_relay
            = [](Tox *tox, const std::string &ip, uint16_t port, const std::vector<uint8_t> &pk,
                  const std::vector<uint8_t> &dht_id) {
                  Tox_Err_Bootstrap err_bs;
                  tox_bootstrap(tox, ip.c_str(), port, dht_id.data(), &err_bs);
                  if (err_bs != TOX_ERR_BOOTSTRAP_OK) {
                      std::cout << "tox_bootstrap failed with " << err_bs << " for " << ip << ":"
                                << port << std::endl;
                  }
                  Tox_Err_Bootstrap err_relay;
                  // Use dht_id for TCP relay as well, as server uses DHT key
                  tox_add_tcp_relay(tox, ip.c_str(), port, dht_id.data(), &err_relay);
                  if (err_relay != TOX_ERR_BOOTSTRAP_OK) {
                      std::cout << "tox_add_tcp_relay failed with " << err_relay << " for " << ip
                                << ":" << port << std::endl;
                  }
              };

        // Connect {C,D} -> A, {E,F} -> B
        connect_to_relay(toxC.get(), ipA, portA, pkA, dhtIdA);
        connect_to_relay(toxD.get(), ipA, portA, pkA, dhtIdA);
        connect_to_relay(toxE.get(), ipB, portB, pkB, dhtIdB);
        connect_to_relay(toxF.get(), ipB, portB, pkB, dhtIdB);

        // B -> A (Connect the two TCP relays, but only one initial link)
        connect_to_relay(toxB.get(), ipA, portA, pkA, dhtIdA);

        // Connect C and F
        uint8_t pkF[TOX_PUBLIC_KEY_SIZE];
        tox_self_get_public_key(toxF.get(), pkF);
        uint8_t pkC[TOX_PUBLIC_KEY_SIZE];
        tox_self_get_public_key(toxC.get(), pkC);

        Tox_Err_Friend_Add err;
        const uint32_t fC = tox_friend_add_norequest(toxC.get(), pkF, &err);
        ASSERT_EQ(err, TOX_ERR_FRIEND_ADD_OK);
        const uint32_t fF = tox_friend_add_norequest(toxF.get(), pkC, &err);
        ASSERT_EQ(err, TOX_ERR_FRIEND_ADD_OK);

        struct Context {
            bool received = false;
        } ctx;

        tox_callback_friend_message(toxF.get(),
            [](Tox *, uint32_t, Tox_Message_Type, const uint8_t *, std::size_t, void *user_data) {
                static_cast<Context *>(user_data)->received = true;
            });

        bool sent = false;
        sim.run_until(
            [&]() {
                tox_iterate(toxA.get(), nullptr);
                tox_iterate(toxB.get(), nullptr);
                tox_iterate(toxC.get(), nullptr);
                tox_iterate(toxD.get(), nullptr);
                tox_iterate(toxE.get(), nullptr);
                tox_iterate(toxF.get(), &ctx);

                Tox_Connection statusC = tox_friend_get_connection_status(toxC.get(), fC, nullptr);
                Tox_Connection statusF = tox_friend_get_connection_status(toxF.get(), fF, nullptr);

                if (kDebug) {
                    static int loop_counter = 0;
                    if (loop_counter++ % 100 == 0) {
                        std::cout << "Conn Status: "
                                  << "A=" << tox_self_get_connection_status(toxA.get()) << " "
                                  << "B=" << tox_self_get_connection_status(toxB.get()) << " "
                                  << "C=" << tox_self_get_connection_status(toxC.get()) << " "
                                  << "D=" << tox_self_get_connection_status(toxC.get()) << " "
                                  << "E=" << tox_self_get_connection_status(toxC.get()) << " "
                                  << "F=" << tox_self_get_connection_status(toxF.get()) << " "
                                  << " Friend Status C->F: " << statusC << ", F->C: " << statusF
                                  << std::endl;
                    }
                }

                if (!sent && statusC != TOX_CONNECTION_NONE) {
                    const uint8_t msg[] = "hello";
                    Tox_Err_Friend_Send_Message send_err;
                    tox_friend_send_message(
                        toxC.get(), fC, TOX_MESSAGE_TYPE_NORMAL, msg, sizeof(msg), &send_err);
                    if (kDebug) {
                        std::cout << "Message sent from C to F, err=" << send_err << std::endl;
                    }
                    sent = true;
                }

                return ctx.received;
            },
            120000);

        EXPECT_TRUE(ctx.received);
    }

}  // namespace
}  // namespace tox::test
