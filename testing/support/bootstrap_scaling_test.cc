// clang-format off
#include "public/simulation.hh"
// clang-format on

#include <gtest/gtest.h>

#include <cstddef>
#include <iostream>
#include <memory>
#include <vector>

#include "../../toxcore/network.h"
#include "../../toxcore/tox.h"

namespace tox::test {
namespace {

    class BootstrapScalingTest : public ::testing::Test {
    protected:
        Simulation sim{12345};
    };

    TEST_F(BootstrapScalingTest, TwentyNodes)
    {
        sim.net().set_verbose(false);
        const int num_nodes = 20;
        std::vector<std::unique_ptr<SimulatedNode>> nodes;
        std::vector<SimulatedNode::ToxPtr> toxes;

        std::cerr << "[Test] Creating " << num_nodes << " nodes..." << std::endl;

        // Create all nodes and tox instances
        for (int i = 0; i < num_nodes; ++i) {
            auto node = sim.create_node();
            auto tox = node->create_tox();
            ASSERT_NE(tox, nullptr) << "Failed to create Tox instance " << i;
            nodes.push_back(std::move(node));
            toxes.push_back(std::move(tox));
        }

        // Node 0 is the bootstrap target
        uint8_t bootstrap_dht_id[TOX_PUBLIC_KEY_SIZE];
        tox_self_get_dht_id(toxes[0].get(), bootstrap_dht_id);

        FakeUdpSocket *main_sock = nodes[0]->get_primary_socket();
        ASSERT_NE(main_sock, nullptr) << "Node 0 has no primary socket";
        uint16_t bootstrap_port = main_sock->local_port();

        char bootstrap_ip[TOX_INET_ADDRSTRLEN];
        ip_parse_addr(&nodes[0]->ip, bootstrap_ip, sizeof(bootstrap_ip));

        std::cerr << "[Test] Bootstrapping to Node 0 at " << bootstrap_ip << ":" << bootstrap_port
                  << std::endl;

        std::size_t total_packets = 0;
        sim.net().add_observer([&](const Packet &) { total_packets++; });

        // Everyone else bootstraps to Node 0
        for (int i = 1; i < num_nodes; ++i) {
            Tox_Err_Bootstrap err;
            bool success = tox_bootstrap(
                toxes[i].get(), bootstrap_ip, bootstrap_port, bootstrap_dht_id, &err);
            ASSERT_TRUE(success) << "Bootstrap call failed for node " << i << ": " << err;
        }

        // Run simulation until everyone is connected or timeout
        const uint64_t virtual_timeout_ms = 300000;
        bool all_connected = false;

        sim.run_until(
            [&]() {
                all_connected = true;
                std::size_t connected_count = 0;
                for (int i = 0; i < num_nodes; ++i) {
                    tox_iterate(toxes[i].get(), nullptr);
                    if (tox_self_get_connection_status(toxes[i].get()) != TOX_CONNECTION_NONE) {
                        connected_count++;
                    } else {
                        all_connected = false;
                    }
                }

                static uint64_t last_print = 0;
                if (sim.clock().current_time_ms() - last_print > 5000) {
                    std::cerr << "[Test] DHT connected: " << connected_count << "/" << num_nodes
                              << " at " << sim.clock().current_time_ms()
                              << "ms. Total packets: " << total_packets << std::endl;
                    last_print = sim.clock().current_time_ms();
                }

                return all_connected;
            },
            virtual_timeout_ms);

        if (!all_connected) {
            std::cerr << "[Test] Bootstrap failed. Status of nodes:" << std::endl;
            for (int i = 0; i < num_nodes; ++i) {
                Tox_Connection status = tox_self_get_connection_status(toxes[i].get());
                if (status == TOX_CONNECTION_NONE) {
                    std::cerr << "  Node " << i << " is NOT connected." << std::endl;
                }
            }
        }

        EXPECT_TRUE(all_connected)
            << "Only " << (num_nodes - (all_connected ? 0 : 1)) << " nodes connected? Check logs.";
    }

}  // namespace
}  // namespace tox::test
