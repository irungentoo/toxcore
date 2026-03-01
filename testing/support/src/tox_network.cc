/* SPDX-License-Identifier: GPL-3.0-or-later
 * Copyright © 2026 The TokTok team.
 */

#include "../public/tox_network.hh"

#include <cstddef>
#include <cstring>
#include <future>
#include <iostream>
#include <vector>

#include "../../../toxcore/network.h"
#include "../../../toxcore/tox.h"
#include "../../../toxcore/tox_events.h"
#include "../public/tox_runner.hh"

namespace tox::test {

ConnectedFriend::~ConnectedFriend() = default;

std::vector<ConnectedFriend> setup_connected_friends(Simulation &sim, Tox *_Nonnull main_tox,
    SimulatedNode &main_node, int num_friends, const Tox_Options *_Nullable options, bool verbose)
{
    std::vector<ConnectedFriend> friends;
    friends.reserve(num_friends);

    uint8_t main_pk[TOX_PUBLIC_KEY_SIZE];
    tox_self_get_public_key(main_tox, main_pk);
    uint8_t main_dht_id[TOX_PUBLIC_KEY_SIZE];
    tox_self_get_dht_id(main_tox, main_dht_id);

    FakeUdpSocket *main_socket = main_node.get_primary_socket();
    if (!main_socket) {
        return {};
    }
    uint16_t main_port = main_socket->local_port();

    char main_ip_str[TOX_INET_ADDRSTRLEN];
    ip_parse_addr(&main_node.ip, main_ip_str, sizeof(main_ip_str));

    uint8_t prev_dht_id[TOX_PUBLIC_KEY_SIZE];
    memcpy(prev_dht_id, main_dht_id, TOX_PUBLIC_KEY_SIZE);
    char prev_ip_str[TOX_INET_ADDRSTRLEN];
    ip_parse_addr(&main_node.ip, prev_ip_str, sizeof(prev_ip_str));
    uint16_t prev_port = main_port;

    for (int i = 0; i < num_friends; ++i) {
        auto node = sim.create_node();
        auto runner = std::make_unique<ToxRunner>(*node, options);

        uint8_t friend_pk[TOX_PUBLIC_KEY_SIZE];
        runner->invoke([&](Tox *_Nonnull tox) { tox_self_get_public_key(tox, friend_pk); });

        Tox_Err_Friend_Add err;
        uint32_t fn = tox_friend_add_norequest(main_tox, friend_pk, &err);
        if (fn == UINT32_MAX || err != TOX_ERR_FRIEND_ADD_OK) {
            return {};
        }

        // Execute add friend and bootstrap on runner
        runner->execute([=](Tox *_Nonnull tox) {
            tox_friend_add_norequest(tox, main_pk, nullptr);
            tox_bootstrap(tox, main_ip_str, main_port, main_dht_id, nullptr);
            if (i > 0) {
                tox_bootstrap(tox, prev_ip_str, prev_port, prev_dht_id, nullptr);
            }
        });

        // Retrieve previous node's DHT ID and update IP for the next iteration.
        // We use invoke to safely fetch data from the runner thread.
        runner->invoke([&](Tox *_Nonnull tox) { tox_self_get_dht_id(tox, prev_dht_id); });

        ip_parse_addr(&node->ip, prev_ip_str, sizeof(prev_ip_str));

        FakeUdpSocket *_Nullable node_socket = node->get_primary_socket();
        if (!node_socket) {
            return {};
        }
        prev_port = node_socket->local_port();

        friends.push_back({std::move(node), std::move(runner), fn});

        // Run the simulation periodically to allow the DHT to stabilize incrementally
        // as we add nodes, rather than waiting until the end.
        if (friends.size() % 10 == 0) {
            sim.run_until([&]() { return false; }, 20);
        }
    }

    if (!friends.empty()) {
        tox_bootstrap(main_tox, prev_ip_str, prev_port, prev_dht_id, nullptr);
    }

    std::vector<bool> friends_connected(friends.size(), false);

    sim.run_until(
        [&]() {
            tox_iterate(main_tox, nullptr);

            // Check connection status
            int connected_count = 0;

            for (std::size_t i = 0; i < friends.size(); ++i) {
                // Check if main sees friend
                bool main_sees_friend
                    = tox_friend_get_connection_status(main_tox, friends[i].friend_number, nullptr)
                    != TOX_CONNECTION_NONE;

                // Check if friend sees main by polling events from the runner
                auto batches = friends[i].runner->poll_events();
                for (const auto &batch : batches) {
                    std::size_t size = tox_events_get_size(batch.get());
                    for (std::size_t k = 0; k < size; ++k) {
                        const Tox_Event *e = tox_events_get(batch.get(), k);
                        if (tox_event_get_type(e) == TOX_EVENT_FRIEND_CONNECTION_STATUS) {
                            auto *ev = tox_event_get_friend_connection_status(e);
                            if (tox_event_friend_connection_status_get_connection_status(ev)
                                != TOX_CONNECTION_NONE) {
                                friends_connected[i] = true;
                            } else {
                                friends_connected[i] = false;
                            }
                        }
                    }
                }

                if (main_sees_friend && friends_connected[i]) {
                    connected_count++;
                }
            }

            if (connected_count == static_cast<int>(friends.size())) {
                return true;
            }

            static uint64_t last_print = 0;
            if (verbose && sim.clock().current_time_ms() - last_print > 1000) {
                std::cerr << "[setup_connected_friends] Friends connected: " << connected_count
                          << "/" << friends.size() << " (time: " << sim.clock().current_time_ms()
                          << "ms)" << std::endl;
                last_print = sim.clock().current_time_ms();
            }

            return false;
        },
        300000);

    return friends;
}

bool connect_friends(Simulation &sim, SimulatedNode &node1, Tox *_Nonnull tox1,
    SimulatedNode &node2, Tox *_Nonnull tox2)
{
    // This helper function assumes the Tox instances are running in the current thread
    // (e.g., standard unit test) or that the caller is handling thread safety if they
    // are part of a runner. It uses direct tox_iterate calls.

    uint8_t pk1[TOX_PUBLIC_KEY_SIZE];
    uint8_t pk2[TOX_PUBLIC_KEY_SIZE];
    tox_self_get_public_key(tox1, pk1);
    tox_self_get_public_key(tox2, pk2);

    Tox_Err_Friend_Add err_add;
    uint32_t f1 = tox_friend_add_norequest(tox1, pk2, &err_add);
    if (f1 == UINT32_MAX || err_add != TOX_ERR_FRIEND_ADD_OK) {
        return false;
    }

    uint32_t f2 = tox_friend_add_norequest(tox2, pk1, &err_add);
    if (f2 == UINT32_MAX || err_add != TOX_ERR_FRIEND_ADD_OK) {
        return false;
    }

    uint8_t dht_id1[TOX_PUBLIC_KEY_SIZE];
    tox_self_get_dht_id(tox1, dht_id1);
    char ip1_str[TOX_INET_ADDRSTRLEN];
    ip_parse_addr(&node1.ip, ip1_str, sizeof(ip1_str));

    FakeUdpSocket *s1 = node1.get_primary_socket();
    if (!s1) {
        return false;
    }
    uint16_t port1 = s1->local_port();

    uint8_t dht_id2[TOX_PUBLIC_KEY_SIZE];
    tox_self_get_dht_id(tox2, dht_id2);
    char ip2_str[TOX_INET_ADDRSTRLEN];
    ip_parse_addr(&node2.ip, ip2_str, sizeof(ip2_str));

    FakeUdpSocket *s2 = node2.get_primary_socket();
    if (!s2) {
        return false;
    }
    uint16_t port2 = s2->local_port();

    tox_bootstrap(tox1, ip2_str, port2, dht_id2, nullptr);
    tox_bootstrap(tox2, ip1_str, port1, dht_id1, nullptr);

    sim.run_until(
        [&]() {
            tox_iterate(tox1, nullptr);
            tox_iterate(tox2, nullptr);
            return tox_friend_get_connection_status(tox1, f1, nullptr) != TOX_CONNECTION_NONE
                && tox_friend_get_connection_status(tox2, f2, nullptr) != TOX_CONNECTION_NONE;
        },
        60000);

    return tox_friend_get_connection_status(tox1, f1, nullptr) != TOX_CONNECTION_NONE
        && tox_friend_get_connection_status(tox2, f2, nullptr) != TOX_CONNECTION_NONE;
}

uint32_t setup_connected_group(
    Simulation &sim, Tox *_Nonnull main_tox, const std::vector<ConnectedFriend> &friends)
{
    struct NodeGroupState {
        uint32_t peer_count = 0;
        uint32_t group_number = UINT32_MAX;
    };

    NodeGroupState main_state;
    tox_callback_group_peer_join(
        main_tox, [](Tox *_Nonnull, uint32_t, uint32_t, void *_Nullable user_data) {
            static_cast<NodeGroupState *>(user_data)->peer_count++;
        });

    Tox_Err_Group_New err_new;
    main_state.group_number = tox_group_new(main_tox, TOX_GROUP_PRIVACY_STATE_PUBLIC,
        reinterpret_cast<const uint8_t *>("test"), 4, reinterpret_cast<const uint8_t *>("main"), 4,
        &err_new);

    if (main_state.group_number == UINT32_MAX || err_new != TOX_ERR_GROUP_NEW_OK) {
        return UINT32_MAX;
    }

    // Friend states tracked via events
    std::vector<NodeGroupState> friend_states(friends.size());

    // Main tox sends invites; friends accept via events polled from their runners.

    bool success = false;
    std::size_t invites_sent = 0;

    sim.run_until(
        [&]() {
            tox_iterate(main_tox, &main_state);

            // Throttle invites
            std::size_t accepted_count = 0;
            for (const auto &fs : friend_states) {
                if (fs.group_number != UINT32_MAX)
                    accepted_count++;
            }

            while (invites_sent < friends.size() && (invites_sent - accepted_count) < 5) {
                Tox_Err_Group_Invite_Friend err_invite;
                if (tox_group_invite_friend(main_tox, main_state.group_number,
                        friends[invites_sent].friend_number, &err_invite)) {
                    invites_sent++;
                } else {
                    break;
                }
            }

            // Process friend events
            for (std::size_t i = 0; i < friends.size(); ++i) {
                auto batches = friends[i].runner->poll_events();
                for (const auto &batch : batches) {
                    std::size_t size = tox_events_get_size(batch.get());
                    for (std::size_t k = 0; k < size; ++k) {
                        const Tox_Event *e = tox_events_get(batch.get(), k);
                        Tox_Event_Type type = tox_event_get_type(e);

                        if (type == TOX_EVENT_GROUP_INVITE) {
                            auto *ev = tox_event_get_group_invite(e);
                            uint32_t friend_number = tox_event_group_invite_get_friend_number(ev);
                            const uint8_t *data = tox_event_group_invite_get_invite_data(ev);
                            std::size_t len = tox_event_group_invite_get_invite_data_length(ev);

                            // Accept invite on runner thread.
                            // We must copy data because the event structure will be freed.
                            std::vector<uint8_t> invite_data(data, data + len);

                            friends[i].runner->execute([=](Tox *_Nonnull tox) {
                                Tox_Err_Group_Invite_Accept err;
                                tox_group_invite_accept(tox, friend_number, invite_data.data(),
                                    invite_data.size(), reinterpret_cast<const uint8_t *>("peer"),
                                    4, nullptr, 0, &err);
                            });
                        } else if (type == TOX_EVENT_GROUP_PEER_JOIN) {
                            friend_states[i].peer_count++;
                        } else if (type == TOX_EVENT_GROUP_SELF_JOIN) {
                            auto *ev = tox_event_get_group_self_join(e);
                            friend_states[i].group_number
                                = tox_event_group_self_join_get_group_number(ev);
                        }
                    }
                }
            }

            if (main_state.peer_count < friends.size())
                return false;

            for (const auto &fs : friend_states) {
                if (fs.group_number == UINT32_MAX || fs.peer_count < friends.size())
                    return false;
            }

            success = true;
            return true;
        },
        300000);

    return success ? main_state.group_number : UINT32_MAX;
}

}  // namespace tox::test
