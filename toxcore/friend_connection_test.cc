#include "friend_connection.h"

#include <gmock/gmock.h>
#include <gtest/gtest.h>

#include <algorithm>
#include <array>
#include <cstring>
#include <functional>
#include <map>
#include <memory>
#include <vector>

#include "../testing/support/public/simulated_environment.hh"
#include "DHT_test_util.hh"
#include "attributes.h"
#include "crypto_core.h"
#include "logger.h"
#include "mono_time.h"
#include "net_crypto.h"
#include "net_profile.h"
#include "network.h"
#include "onion_client.h"
#include "test_util.hh"

namespace {

using namespace tox::test;

// --- Helper Class ---

template <typename DHTWrapper>
class FriendConnTestNode {
public:
    FriendConnTestNode(SimulatedEnvironment &env, std::uint16_t port)
        : dht_wrapper_(env, port)
        , net_profile_(netprof_new(dht_wrapper_.logger(), &dht_wrapper_.node().c_memory),
              [mem = &dht_wrapper_.node().c_memory](Net_Profile *p) { netprof_kill(mem, p); })
        , net_crypto_(nullptr, [](Net_Crypto *c) { kill_net_crypto(c); })
        , onion_client_(nullptr, [](Onion_Client *c) { kill_onion_client(c); })
        , friend_connections_(nullptr, [](Friend_Connections *c) { kill_friend_connections(c); })
    {
        logger_callback_log(
            dht_wrapper_.logger(),
            [](void *_Nullable context, Logger_Level level, const char *_Nonnull file,
                std::uint32_t line, const char *_Nonnull func, const char *_Nonnull message,
                void *_Nullable userdata) {
                fprintf(stderr, "[%d] %s:%u: %s: %s\n", level, file, line, func, message);
            },
            nullptr, nullptr);

        // Setup NetCrypto
        TCP_Proxy_Info proxy_info = {{0}, TCP_PROXY_NONE};
        net_crypto_.reset(new_net_crypto(dht_wrapper_.logger(), &dht_wrapper_.node().c_memory,
            &dht_wrapper_.node().c_random, &dht_wrapper_.node().c_network, dht_wrapper_.mono_time(),
            dht_wrapper_.networking(), dht_wrapper_.get_dht(), &DHTWrapper::funcs, &proxy_info,
            net_profile_.get()));

        new_keys(net_crypto_.get());

        // Setup Onion Client
        onion_client_.reset(new_onion_client(dht_wrapper_.logger(), &dht_wrapper_.node().c_memory,
            &dht_wrapper_.node().c_random, dht_wrapper_.mono_time(), net_crypto_.get(),
            dht_wrapper_.get_dht(), dht_wrapper_.networking()));

        // Setup Friend Connections
        friend_connections_.reset(
            new_friend_connections(dht_wrapper_.logger(), &dht_wrapper_.node().c_memory,
                dht_wrapper_.mono_time(), &dht_wrapper_.node().c_network, onion_client_.get(),
                dht_wrapper_.get_dht(), net_crypto_.get(), dht_wrapper_.networking(), true));
    }

    Friend_Connections *_Nonnull get_friend_connections()
    {
        return REQUIRE_NOT_NULL(friend_connections_.get());
    }
    Onion_Client *_Nonnull get_onion_client() { return REQUIRE_NOT_NULL(onion_client_.get()); }
    Net_Crypto *_Nonnull get_net_crypto() { return REQUIRE_NOT_NULL(net_crypto_.get()); }
    DHT *_Nonnull get_dht() { return dht_wrapper_.get_dht(); }
    const std::uint8_t *dht_public_key() const { return dht_wrapper_.dht_public_key(); }
    const std::uint8_t *real_public_key() const
    {
        return nc_get_self_public_key(net_crypto_.get());
    }
    const Random *get_random() { return &dht_wrapper_.node().c_random; }

    IP_Port get_ip_port() const { return dht_wrapper_.get_ip_port(); }

    void poll()
    {
        dht_wrapper_.poll();
        do_net_crypto(net_crypto_.get(), nullptr);
        do_onion_client(onion_client_.get());
        do_friend_connections(friend_connections_.get(), nullptr);
    }

    ~FriendConnTestNode();

private:
    DHTWrapper dht_wrapper_;
    std::unique_ptr<Net_Profile, std::function<void(Net_Profile *)>> net_profile_;
    std::unique_ptr<Net_Crypto, void (*)(Net_Crypto *)> net_crypto_;
    std::unique_ptr<Onion_Client, void (*)(Onion_Client *)> onion_client_;
    std::unique_ptr<Friend_Connections, void (*)(Friend_Connections *)> friend_connections_;
};

template <typename DHTWrapper>
FriendConnTestNode<DHTWrapper>::~FriendConnTestNode() = default;

using FriendConnNode = FriendConnTestNode<WrappedDHT>;

class FriendConnectionTest : public ::testing::Test {
protected:
    SimulatedEnvironment env{12345};
};

TEST_F(FriendConnectionTest, CreationAndDestruction)
{
    FriendConnNode alice(env, 33445);
    EXPECT_NE(alice.get_friend_connections(), nullptr);
}

TEST_F(FriendConnectionTest, AddKillConnection)
{
    FriendConnNode alice(env, 33445);
    std::uint8_t friend_pk[CRYPTO_PUBLIC_KEY_SIZE];
    std::uint8_t friend_sk[CRYPTO_SECRET_KEY_SIZE];
    crypto_new_keypair(alice.get_random(), friend_pk, friend_sk);

    // Add Connection
    int conn_id = new_friend_connection(alice.get_friend_connections(), friend_pk);
    EXPECT_NE(conn_id, -1);

    // Verify status (should be connecting or none initially, but ID is valid)
    EXPECT_NE(
        friend_con_connected(alice.get_friend_connections(), conn_id), FRIENDCONN_STATUS_NONE);

    // Kill Connection
    EXPECT_EQ(kill_friend_connection(alice.get_friend_connections(), conn_id), 0);
}

TEST_F(FriendConnectionTest, ConnectTwoNodes)
{
    FriendConnNode alice(env, 33445);
    FriendConnNode bob(env, 33446);

    // Alice adds Bob as friend
    int alice_conn_id
        = new_friend_connection(alice.get_friend_connections(), bob.real_public_key());
    ASSERT_NE(alice_conn_id, -1);

    // Bob adds Alice as friend
    int bob_conn_id = new_friend_connection(bob.get_friend_connections(), alice.real_public_key());
    ASSERT_NE(bob_conn_id, -1);

    // Helper to inject peer info into DHT and trigger connection
    auto inject_peer = [](FriendConnNode &self, const FriendConnNode &peer, int conn_id) {
        // 1. Tell DHT where the peer is (IP/Port + DHT Public Key)
        IP_Port peer_ip = peer.get_ip_port();
        addto_lists(self.get_dht(), &peer_ip, peer.dht_public_key());

        // 2. Tell friend_connection the peer's DHT Public Key (normally found via Onion)
        set_dht_temp_pk(self.get_friend_connections(), conn_id, peer.dht_public_key(), nullptr);
    };

    inject_peer(alice, bob, alice_conn_id);
    inject_peer(bob, alice, bob_conn_id);

    auto start = env.clock().current_time_ms();
    bool connected = false;

    while ((env.clock().current_time_ms() - start) < 5000) {  // 5 seconds timeout
        alice.poll();
        bob.poll();
        env.advance_time(10);

        if (friend_con_connected(alice.get_friend_connections(), alice_conn_id)
                == FRIENDCONN_STATUS_CONNECTED
            && friend_con_connected(bob.get_friend_connections(), bob_conn_id)
                == FRIENDCONN_STATUS_CONNECTED) {
            connected = true;
            break;
        }
    }

    EXPECT_TRUE(connected) << "Alice and Bob failed to connect";
}

}  // namespace
