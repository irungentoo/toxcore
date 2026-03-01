#include "onion_client.h"

#include <gmock/gmock.h>
#include <gtest/gtest.h>

#include <algorithm>
#include <array>
#include <cstddef>
#include <cstring>
#include <functional>
#include <iostream>
#include <map>
#include <memory>
#include <set>
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
#include "onion.h"
#include "onion_announce.h"

namespace {

using namespace tox::test;

// --- Helper Class ---

template <typename DHTWrapper>
class OnionTestNode {
public:
    OnionTestNode(SimulatedEnvironment &env, std::uint16_t port)
        : dht_wrapper_(env, port)
        , net_profile_(netprof_new(dht_wrapper_.logger(), &dht_wrapper_.node().c_memory),
              [mem = &dht_wrapper_.node().c_memory](Net_Profile *p) { netprof_kill(mem, p); })
        , net_crypto_(nullptr, [](Net_Crypto *c) { kill_net_crypto(c); })
        , onion_client_(nullptr, [](Onion_Client *c) { kill_onion_client(c); })
        , onion_server_(nullptr, [](Onion *o) { kill_onion(o); })
        , onion_announce_(nullptr, [](Onion_Announce *a) { kill_onion_announce(a); })
    {
        // Setup NetCrypto
        TCP_Proxy_Info proxy_info = {{0}, TCP_PROXY_NONE};
        net_crypto_.reset(new_net_crypto(dht_wrapper_.logger(), &dht_wrapper_.node().c_memory,
            &dht_wrapper_.node().c_random, &dht_wrapper_.node().c_network, dht_wrapper_.mono_time(),
            dht_wrapper_.networking(), dht_wrapper_.get_dht(), &DHTWrapper::funcs, &proxy_info,
            net_profile_.get()));

        // Setup Onion Client
        onion_client_.reset(new_onion_client(dht_wrapper_.logger(), &dht_wrapper_.node().c_memory,
            &dht_wrapper_.node().c_random, dht_wrapper_.mono_time(), net_crypto_.get(),
            dht_wrapper_.get_dht(), dht_wrapper_.networking()));

        // Setup Onion Server
        onion_server_.reset(new_onion(dht_wrapper_.logger(), &dht_wrapper_.node().c_memory,
            dht_wrapper_.mono_time(), &dht_wrapper_.node().c_random, dht_wrapper_.get_dht(),
            dht_wrapper_.networking()));

        // Setup Onion Announce
        onion_announce_.reset(new_onion_announce(dht_wrapper_.logger(),
            &dht_wrapper_.node().c_memory, &dht_wrapper_.node().c_random, dht_wrapper_.mono_time(),
            dht_wrapper_.get_dht(), dht_wrapper_.networking()));
    }

    Onion_Client *_Nonnull get_onion_client() { return REQUIRE_NOT_NULL(onion_client_.get()); }
    Net_Crypto *_Nonnull get_net_crypto() { return REQUIRE_NOT_NULL(net_crypto_.get()); }
    DHT *_Nonnull get_dht() { return dht_wrapper_.get_dht(); }
    Logger *_Nonnull get_logger() { return dht_wrapper_.logger(); }
    const std::uint8_t *_Nonnull dht_public_key() const { return dht_wrapper_.dht_public_key(); }
    const std::uint8_t *_Nonnull real_public_key() const
    {
        return nc_get_self_public_key(net_crypto_.get());
    }
    const std::uint8_t *_Nonnull dht_secret_key() const { return dht_wrapper_.dht_secret_key(); }
    const Random *_Nonnull get_random() { return &dht_wrapper_.node().c_random; }

    IP_Port get_ip_port() const { return dht_wrapper_.get_ip_port(); }
    tox::test::ScopedToxSystem &node() { return dht_wrapper_.node(); }
    Onion_Announce *_Nonnull get_onion_announce()
    {
        return REQUIRE_NOT_NULL(onion_announce_.get());
    }

    void poll(bool poll_onion = true)
    {
        dht_wrapper_.poll();
        do_net_crypto(net_crypto_.get(), nullptr);
        if (poll_onion)
            do_onion_client(onion_client_.get());
    }

    ~OnionTestNode();

private:
    DHTWrapper dht_wrapper_;
    std::unique_ptr<Net_Profile, std::function<void(Net_Profile *)>> net_profile_;
    std::unique_ptr<Net_Crypto, void (*)(Net_Crypto *)> net_crypto_;
    std::unique_ptr<Onion_Client, void (*)(Onion_Client *)> onion_client_;
    std::unique_ptr<Onion, void (*)(Onion *)> onion_server_;
    std::unique_ptr<Onion_Announce, void (*)(Onion_Announce *)> onion_announce_;
};

template <typename DHTWrapper>
OnionTestNode<DHTWrapper>::~OnionTestNode() = default;

using OnionNode = OnionTestNode<WrappedDHT>;

class OnionClientTest : public ::testing::Test {
public:
    static void print_log(void *context, Logger_Level level, const char *file, std::uint32_t line,
        const char *func, const char *message, void *userdata)
    {
        if (level == LOGGER_LEVEL_TRACE)
            return;
        fprintf(stderr, "[%d] %s:%u %s: %s\n", level, file, line, func, message);
    }

protected:
    SimulatedEnvironment env{12345};
};

TEST_F(OnionClientTest, CreationAndDestruction)
{
    OnionNode alice(env, 33445);
    EXPECT_NE(alice.get_onion_client(), nullptr);
}

TEST_F(OnionClientTest, FriendManagement)
{
    OnionNode alice(env, 33445);
    std::uint8_t friend_pk[CRYPTO_PUBLIC_KEY_SIZE];
    std::uint8_t friend_sk[CRYPTO_SECRET_KEY_SIZE];
    crypto_new_keypair(alice.get_random(), friend_pk, friend_sk);

    // Add Friend
    int friend_num = onion_addfriend(alice.get_onion_client(), friend_pk);
    ASSERT_NE(friend_num, -1);

    // Check Friend Num
    EXPECT_EQ(onion_friend_num(alice.get_onion_client(), friend_pk), friend_num);

    // Add Same Friend Again
    EXPECT_EQ(onion_addfriend(alice.get_onion_client(), friend_pk), friend_num);

    // Check Friend Count
    EXPECT_EQ(onion_get_friend_count(alice.get_onion_client()), 1);

    // Delete Friend
    EXPECT_NE(onion_delfriend(alice.get_onion_client(), friend_num), -1);
    EXPECT_EQ(onion_get_friend_count(alice.get_onion_client()), 0);

    // Check Friend Num after deletion
    EXPECT_EQ(onion_friend_num(alice.get_onion_client(), friend_pk), -1);

    // Delete Invalid Friend
    EXPECT_EQ(onion_delfriend(alice.get_onion_client(), friend_num), -1);
}

TEST_F(OnionClientTest, FriendStatus)
{
    OnionNode alice(env, 33445);
    std::uint8_t friend_pk[CRYPTO_PUBLIC_KEY_SIZE];
    std::uint8_t friend_sk[CRYPTO_SECRET_KEY_SIZE];
    crypto_new_keypair(alice.get_random(), friend_pk, friend_sk);

    int friend_num = onion_addfriend(alice.get_onion_client(), friend_pk);
    ASSERT_NE(friend_num, -1);

    // Set DHT Key so we can get IP
    std::uint8_t dht_key[CRYPTO_PUBLIC_KEY_SIZE];
    crypto_new_keypair(alice.get_random(), dht_key, friend_sk);
    EXPECT_EQ(onion_set_friend_dht_pubkey(alice.get_onion_client(), friend_num, dht_key), 0);

    std::uint32_t lock_token;
    EXPECT_EQ(
        dht_addfriend(alice.get_dht(), dht_key, nullptr, nullptr, friend_num, &lock_token), 0);

    // Set Online
    EXPECT_EQ(onion_set_friend_online(alice.get_onion_client(), friend_num, true), 0);

    // Get Friend IP (should be 0 as not connected)
    IP_Port ip;
    EXPECT_EQ(onion_getfriendip(alice.get_onion_client(), friend_num, &ip), 0);

    // Set Offline
    EXPECT_EQ(onion_set_friend_online(alice.get_onion_client(), friend_num, false), 0);

    // Invalid friend num
    EXPECT_EQ(onion_set_friend_online(alice.get_onion_client(), 12345, true), -1);
}

TEST_F(OnionClientTest, DHTKey)
{
    OnionNode alice(env, 33445);
    std::uint8_t friend_pk[CRYPTO_PUBLIC_KEY_SIZE];
    std::uint8_t friend_sk[CRYPTO_SECRET_KEY_SIZE];
    crypto_new_keypair(alice.get_random(), friend_pk, friend_sk);

    int friend_num = onion_addfriend(alice.get_onion_client(), friend_pk);
    ASSERT_NE(friend_num, -1);

    std::uint8_t dht_key[CRYPTO_PUBLIC_KEY_SIZE];
    crypto_new_keypair(alice.get_random(), dht_key, friend_sk);

    // Set DHT Key
    EXPECT_EQ(onion_set_friend_dht_pubkey(alice.get_onion_client(), friend_num, dht_key), 0);

    // Get DHT Key
    std::uint8_t retrieved_key[CRYPTO_PUBLIC_KEY_SIZE];
    EXPECT_EQ(onion_getfriend_dht_pubkey(alice.get_onion_client(), friend_num, retrieved_key), 1);
    EXPECT_EQ(std::memcmp(dht_key, retrieved_key, CRYPTO_PUBLIC_KEY_SIZE), 0);

    // Invalid friend
    EXPECT_EQ(onion_set_friend_dht_pubkey(alice.get_onion_client(), 12345, dht_key), -1);
    EXPECT_EQ(onion_getfriend_dht_pubkey(alice.get_onion_client(), 12345, retrieved_key), 0);
}

TEST_F(OnionClientTest, BootstrapNodes)
{
    OnionNode alice(env, 33445);
    IP_Port ip_port;
    ip_init(&ip_port.ip, 1);
    ip_port.port = 1234;
    std::uint8_t pk[CRYPTO_PUBLIC_KEY_SIZE];
    crypto_new_keypair(alice.get_random(), pk, pk);

    EXPECT_TRUE(onion_add_bs_path_node(alice.get_onion_client(), &ip_port, pk));

    Node_format nodes[MAX_ONION_CLIENTS];
    std::uint16_t count = onion_backup_nodes(alice.get_onion_client(), nodes, MAX_ONION_CLIENTS);
    EXPECT_GE(count, 0);
}

TEST_F(OnionClientTest, ConnectionStatus)
{
    OnionNode alice(env, 33445);
    Onion_Connection_Status status = onion_connection_status(alice.get_onion_client());
    EXPECT_GE(status, ONION_CONNECTION_STATUS_NONE);
    EXPECT_LE(status, ONION_CONNECTION_STATUS_UDP);
}

TEST_F(OnionClientTest, GroupChatHelpers)
{
    OnionNode alice(env, 33445);
    std::uint8_t friend_pk[CRYPTO_PUBLIC_KEY_SIZE];
    std::uint8_t friend_sk[CRYPTO_SECRET_KEY_SIZE];
    crypto_new_keypair(alice.get_random(), friend_pk, friend_sk);

    int friend_num = onion_addfriend(alice.get_onion_client(), friend_pk);
    ASSERT_NE(friend_num, -1);

    Onion_Friend *friend_obj = onion_get_friend(alice.get_onion_client(), friend_num);
    EXPECT_NE(friend_obj, nullptr);

    // Test Group Chat Public Key
    std::uint8_t gc_pk[CRYPTO_PUBLIC_KEY_SIZE];
    crypto_new_keypair(alice.get_random(), gc_pk, friend_sk);

    onion_friend_set_gc_public_key(friend_obj, gc_pk);
    const std::uint8_t *retrieved_gc_pk = onion_friend_get_gc_public_key(friend_obj);
    EXPECT_EQ(std::memcmp(gc_pk, retrieved_gc_pk, CRYPTO_PUBLIC_KEY_SIZE), 0);

    // Test Group Chat Flag
    EXPECT_FALSE(onion_friend_is_groupchat(friend_obj));
    std::uint8_t data[] = {1, 2, 3};
    onion_friend_set_gc_data(friend_obj, data, sizeof(data));
    EXPECT_TRUE(onion_friend_is_groupchat(friend_obj));
}

TEST_F(OnionClientTest, OOBReadInHandleAnnounceResponse)
{
    constexpr bool kEnableLogging = false;

    OnionNode alice(env, 33445);
    if (kEnableLogging) {
        logger_callback_log(alice.get_logger(), OnionClientTest::print_log, nullptr, nullptr);
    }
    WrappedDHT bob(env, 12345);
    FakeUdpSocket *bob_socket = bob.node().endpoint;

    IP_Port bob_ip = bob.get_ip_port();
    const std::uint8_t *bob_pk = bob.dht_public_key();
    const std::uint8_t *bob_sk = bob.dht_secret_key();

    // Bootstrap Alice to Bob
    dht_bootstrap(alice.get_dht(), &bob_ip, bob_pk);

    // Add Bob as Onion Bootstrap node
    onion_add_bs_path_node(alice.get_onion_client(), &bob_ip, bob_pk);

    // Get internal state
    std::uint64_t initial_recv_time = onion_testonly_get_last_packet_recv(alice.get_onion_client());

    // Setup Memory
    Memory mem_struct = env.fake_memory().c_memory();
    const Memory *mem = &mem_struct;

    // Observer
    bool triggered = false;
    bob_socket->set_recv_observer([&](const std::vector<std::uint8_t> &data, const IP_Port &from) {
        if (triggered)
            return;
        if (data.size() < 1 + CRYPTO_NONCE_SIZE + CRYPTO_PUBLIC_KEY_SIZE + CRYPTO_MAC_SIZE)
            return;

        // Layer 1
        if (data[0] != NET_PACKET_ONION_SEND_INITIAL)
            return;

        std::uint8_t shared_key[CRYPTO_SHARED_KEY_SIZE];
        std::uint8_t nonce[CRYPTO_NONCE_SIZE];
        std::memcpy(nonce, data.data() + 1, CRYPTO_NONCE_SIZE);
        const std::uint8_t *ephem_pk = data.data() + 1 + CRYPTO_NONCE_SIZE;

        encrypt_precompute(ephem_pk, bob_sk, shared_key);

        std::vector<std::uint8_t> decrypted1(
            data.size() - (1 + CRYPTO_NONCE_SIZE + CRYPTO_PUBLIC_KEY_SIZE + CRYPTO_MAC_SIZE));
        int dlen = decrypt_data_symmetric(mem, shared_key, nonce,
            data.data() + 1 + CRYPTO_NONCE_SIZE + CRYPTO_PUBLIC_KEY_SIZE,
            data.size() - (1 + CRYPTO_NONCE_SIZE + CRYPTO_PUBLIC_KEY_SIZE), decrypted1.data());
        if (dlen <= 0)
            return;

        // Decrypted 1: [IP] [PK] [Encrypted 2]
        std::size_t offset = SIZE_IPPORT + CRYPTO_PUBLIC_KEY_SIZE;
        if (static_cast<std::size_t>(dlen) <= offset + CRYPTO_MAC_SIZE)
            return;
        ephem_pk = decrypted1.data() + SIZE_IPPORT;

        encrypt_precompute(ephem_pk, bob_sk, shared_key);

        std::vector<std::uint8_t> decrypted2(dlen - offset - CRYPTO_MAC_SIZE);
        dlen = decrypt_data_symmetric(
            mem, shared_key, nonce, decrypted1.data() + offset, dlen - offset, decrypted2.data());
        if (dlen <= 0)
            return;

        // Decrypted 2: [IP] [PK] [Encrypted 3]
        if (static_cast<std::size_t>(dlen) <= offset + CRYPTO_MAC_SIZE)
            return;
        ephem_pk = decrypted2.data() + SIZE_IPPORT;
        encrypt_precompute(ephem_pk, bob_sk, shared_key);

        std::vector<std::uint8_t> decrypted3(dlen - offset - CRYPTO_MAC_SIZE);
        dlen = decrypt_data_symmetric(
            mem, shared_key, nonce, decrypted2.data() + offset, dlen - offset, decrypted3.data());
        if (dlen <= 0)
            return;

        // Decrypted 3: [IP] [Data]
        std::size_t data_offset = SIZE_IPPORT;
        if (static_cast<std::size_t>(dlen) <= data_offset)
            return;
        std::uint8_t *req = decrypted3.data() + data_offset;
        std::size_t req_len = dlen - data_offset;

        // Announce Request: [131] [Nonce] [Alice PK] [Encrypted]
        if (req[0] != 0x87 && req[0] != 0x83)
            return;

        std::uint8_t req_nonce[CRYPTO_NONCE_SIZE];
        std::memcpy(req_nonce, req + 1, CRYPTO_NONCE_SIZE);
        std::uint8_t alice_pk[CRYPTO_PUBLIC_KEY_SIZE];
        std::memcpy(alice_pk, req + 1 + CRYPTO_NONCE_SIZE, CRYPTO_PUBLIC_KEY_SIZE);

        std::uint8_t *req_enc = req + 1 + CRYPTO_NONCE_SIZE + CRYPTO_PUBLIC_KEY_SIZE;
        std::size_t req_enc_len = req_len - (1 + CRYPTO_NONCE_SIZE + CRYPTO_PUBLIC_KEY_SIZE);

        std::vector<std::uint8_t> req_plain(req_enc_len - CRYPTO_MAC_SIZE);
        int plen = decrypt_data(
            mem, alice_pk, bob_sk, req_nonce, req_enc, req_enc_len, req_plain.data());

        if (plen <= 0)
            return;

        // Payload: [Ping ID (32)] [Search ID (32)] [Data PK (32)] [Sendback (Rest)]
        std::size_t sendback_offset = 32 + 32 + 32;
        if (static_cast<std::size_t>(plen) < sendback_offset + ONION_ANNOUNCE_SENDBACK_DATA_LENGTH)
            return;
        std::uint8_t *sendback = req_plain.data() + sendback_offset;
        std::size_t sendback_len = ONION_ANNOUNCE_SENDBACK_DATA_LENGTH;

        // Construct Malicious Response
        std::vector<std::uint8_t> resp;
        resp.push_back(NET_PACKET_ANNOUNCE_RESPONSE);
        resp.insert(resp.end(), sendback, sendback + sendback_len);

        std::uint8_t resp_nonce[CRYPTO_NONCE_SIZE];
        random_nonce(alice.get_random(), resp_nonce);
        resp.insert(resp.end(), resp_nonce, resp_nonce + CRYPTO_NONCE_SIZE);

        // Encrypted Payload: [is_stored (1)] [ping_id (32)]
        // Total 33 bytes. OMIT count.
        std::vector<std::uint8_t> payload(33, 0);

        std::vector<std::uint8_t> ciphertext(33 + CRYPTO_MAC_SIZE);
        encrypt_data(mem, alice_pk, bob_sk, resp_nonce, payload.data(), 33, ciphertext.data());

        resp.insert(resp.end(), ciphertext.begin(), ciphertext.end());

        // Send to Alice
        bob_socket->sendto(resp.data(), resp.size(), &from);
        triggered = true;
    });

    // Run simulation
    for (int i = 0; i < 200; ++i) {
        env.advance_time(50);
        alice.poll();
        bob.poll();
        if (triggered) {
            // Give Alice time to process the malicious packet
            env.advance_time(50);
            alice.poll();
            break;
        }
    }

    ASSERT_TRUE(triggered) << "Failed to trigger vulnerability (Alice didn't send announce request "
                              "or we failed to parse it)";

    // Check if the packet was accepted
    // If accepted, last_packet_recv should be updated
    std::uint64_t final_recv_time = onion_testonly_get_last_packet_recv(alice.get_onion_client());

    // IF the vulnerability is present, the code accepts the packet and updates last_packet_recv.
    // We want the test to FAIL if vulnerability is present.
    // So we Assert that the packet was NOT accepted.
    EXPECT_EQ(initial_recv_time, final_recv_time)
        << "Vulnerability Present: Malformed packet was accepted!";
}

TEST_F(OnionClientTest, DISABLED_IntegerOverflowNumFriends)
{
    OnionNode alice(env, 33445);
    std::uint8_t friend_pk[CRYPTO_PUBLIC_KEY_SIZE];
    std::memset(friend_pk, 0, sizeof(friend_pk));

    // Add 65536 friends to trigger integer overflow of std::uint16_t num_friends
    // This loop demonstrates that we can add enough friends to wrap the counter.
    for (int i = 0; i < 65536; ++i) {
        // Ensure unique public key
        std::memcpy(friend_pk, &i, sizeof(int));

        int res = onion_addfriend(alice.get_onion_client(), friend_pk);
        if (res == -1) {
            FAIL() << "Failed to add friend " << i << ". May be out of memory.";
        }
    }

    // After 65536 adds, num_friends should be 65536 (no overflow with std::uint32_t)
    EXPECT_EQ(onion_get_friend_count(alice.get_onion_client()), 65536);

    // Add one more friend with a GUARANTEED unique key.
    // Previous keys only modified first 4 bytes.
    // Setting the last byte ensures uniqueness against all 65536 previous keys.
    std::memset(friend_pk, 0, sizeof(friend_pk));
    friend_pk[CRYPTO_PUBLIC_KEY_SIZE - 1] = 1;

    int res = onion_addfriend(alice.get_onion_client(), friend_pk);
    EXPECT_EQ(res, 65536) << "Failed to add extra friend. Got index: " << res;
    EXPECT_EQ(onion_get_friend_count(alice.get_onion_client()), 65537);

    // Now demonstrate access is safe.
    Onion_Friend *f = onion_get_friend(alice.get_onion_client(), 65536);
    // Dereferencing 'f' triggers ASAN error if OOB.
    onion_friend_get_gc_public_key(f);
}

TEST_F(OnionClientTest, OnionAnnounceResponse_TooShort)
{
    constexpr bool kEnableLogging = false;

    OnionNode alice(env, 33445);
    if (kEnableLogging) {
        logger_callback_log(alice.get_logger(), OnionClientTest::print_log, nullptr, nullptr);
    }
    WrappedDHT bob(env, 12345);
    if (kEnableLogging) {
        logger_callback_log(bob.logger(), OnionClientTest::print_log, nullptr, nullptr);
    }
    FakeUdpSocket *bob_socket = bob.node().endpoint;

    IP_Port bob_ip = bob.get_ip_port();
    const std::uint8_t *bob_pk = bob.dht_public_key();
    const std::uint8_t *bob_sk = bob.dht_secret_key();

    dht_bootstrap(alice.get_dht(), &bob_ip, bob_pk);
    onion_add_bs_path_node(alice.get_onion_client(), &bob_ip, bob_pk);

    std::uint64_t initial_recv_time = onion_testonly_get_last_packet_recv(alice.get_onion_client());
    bool triggered = false;

    // Setup Memory
    Memory mem_struct = env.fake_memory().c_memory();
    const Memory *mem = &mem_struct;

    bob_socket->set_recv_observer([&](const std::vector<std::uint8_t> &data, const IP_Port &from) {
        if (triggered)
            return;
        if (data.size() < 1 + CRYPTO_NONCE_SIZE + CRYPTO_PUBLIC_KEY_SIZE + CRYPTO_MAC_SIZE)
            return;

        if (data[0] != NET_PACKET_ONION_SEND_INITIAL)
            return;

        std::uint8_t shared_key[CRYPTO_SHARED_KEY_SIZE];
        std::uint8_t nonce[CRYPTO_NONCE_SIZE];
        std::memcpy(nonce, data.data() + 1, CRYPTO_NONCE_SIZE);
        const std::uint8_t *ephem_pk = data.data() + 1 + CRYPTO_NONCE_SIZE;

        encrypt_precompute(ephem_pk, bob_sk, shared_key);

        std::vector<std::uint8_t> decrypted1(
            data.size() - (1 + CRYPTO_NONCE_SIZE + CRYPTO_PUBLIC_KEY_SIZE + CRYPTO_MAC_SIZE));
        int dlen = decrypt_data_symmetric(mem, shared_key, nonce,
            data.data() + 1 + CRYPTO_NONCE_SIZE + CRYPTO_PUBLIC_KEY_SIZE,
            data.size() - (1 + CRYPTO_NONCE_SIZE + CRYPTO_PUBLIC_KEY_SIZE), decrypted1.data());
        if (dlen <= 0)
            return;

        std::size_t offset = SIZE_IPPORT + CRYPTO_PUBLIC_KEY_SIZE;
        if (static_cast<std::size_t>(dlen) <= offset + CRYPTO_MAC_SIZE)
            return;
        ephem_pk = decrypted1.data() + SIZE_IPPORT;

        encrypt_precompute(ephem_pk, bob_sk, shared_key);

        std::vector<std::uint8_t> decrypted2(dlen - offset - CRYPTO_MAC_SIZE);
        dlen = decrypt_data_symmetric(
            mem, shared_key, nonce, decrypted1.data() + offset, dlen - offset, decrypted2.data());
        if (dlen <= 0)
            return;

        if (static_cast<std::size_t>(dlen) <= offset + CRYPTO_MAC_SIZE)
            return;
        ephem_pk = decrypted2.data() + SIZE_IPPORT;
        encrypt_precompute(ephem_pk, bob_sk, shared_key);

        std::vector<std::uint8_t> decrypted3(dlen - offset - CRYPTO_MAC_SIZE);
        dlen = decrypt_data_symmetric(
            mem, shared_key, nonce, decrypted2.data() + offset, dlen - offset, decrypted3.data());
        if (dlen <= 0)
            return;

        std::size_t data_offset = SIZE_IPPORT;
        if (static_cast<std::size_t>(dlen) <= data_offset)
            return;
        std::uint8_t *req = decrypted3.data() + data_offset;
        std::size_t req_len = dlen - data_offset;

        if (req[0] != 0x87 && req[0] != 0x83)
            return;

        std::uint8_t req_nonce[CRYPTO_NONCE_SIZE];
        std::memcpy(req_nonce, req + 1, CRYPTO_NONCE_SIZE);
        std::uint8_t alice_pk[CRYPTO_PUBLIC_KEY_SIZE];
        std::memcpy(alice_pk, req + 1 + CRYPTO_NONCE_SIZE, CRYPTO_PUBLIC_KEY_SIZE);

        std::uint8_t *req_enc = req + 1 + CRYPTO_NONCE_SIZE + CRYPTO_PUBLIC_KEY_SIZE;
        std::size_t req_enc_len = req_len - (1 + CRYPTO_NONCE_SIZE + CRYPTO_PUBLIC_KEY_SIZE);

        std::vector<std::uint8_t> req_plain(req_enc_len - CRYPTO_MAC_SIZE);
        int plen = decrypt_data(
            mem, alice_pk, bob_sk, req_nonce, req_enc, req_enc_len, req_plain.data());

        if (plen <= 0)
            return;

        std::size_t sendback_offset = 32 + 32 + 32;
        if (static_cast<std::size_t>(plen) < sendback_offset + ONION_ANNOUNCE_SENDBACK_DATA_LENGTH)
            return;
        std::uint8_t *sendback = req_plain.data() + sendback_offset;
        std::size_t sendback_len = ONION_ANNOUNCE_SENDBACK_DATA_LENGTH;

        std::vector<std::uint8_t> resp;
        resp.push_back(NET_PACKET_ANNOUNCE_RESPONSE);
        resp.insert(resp.end(), sendback, sendback + sendback_len);

        std::uint8_t resp_nonce[CRYPTO_NONCE_SIZE];
        random_nonce(alice.get_random(), resp_nonce);
        resp.insert(resp.end(), resp_nonce, resp_nonce + CRYPTO_NONCE_SIZE);

        // PAYLOAD SIZE 33 (1 + 32)
        // This is exactly what triggers the missing byte read for nodes_count
        std::vector<std::uint8_t> payload(33, 0);

        std::vector<std::uint8_t> ciphertext(payload.size() + CRYPTO_MAC_SIZE);
        encrypt_data(
            mem, alice_pk, bob_sk, resp_nonce, payload.data(), payload.size(), ciphertext.data());

        resp.insert(resp.end(), ciphertext.begin(), ciphertext.end());

        bob_socket->sendto(resp.data(), resp.size(), &from);
        triggered = true;
    });

    for (int i = 0; i < 200; ++i) {
        env.advance_time(50);
        alice.poll();
        bob.poll();
        if (triggered) {
            env.advance_time(50);
            alice.poll();
            break;
        }
    }

    ASSERT_TRUE(triggered);
    EXPECT_EQ(onion_testonly_get_last_packet_recv(alice.get_onion_client()), initial_recv_time);
}

TEST_F(OnionClientTest, SharedKeyCacheUseAfterFreeRegression)
{
    OnionNode alice(env, 33445);
    OnionNode bob(env, 33446);
    OnionNode charlie(env, 33447);
    OnionNode dave(env, 33448);

    std::vector<OnionNode *> nodes = {&bob, &charlie, &dave};

    // Make everyone know everyone via bootstrap
    for (auto n1 : nodes) {
        for (auto n2 : nodes) {
            if (n1 == n2)
                continue;
            IP_Port ip = n2->get_ip_port();
            dht_bootstrap(n1->get_dht(), &ip, n2->dht_public_key());
        }
    }

    for (auto node : nodes) {
        IP_Port ip = node->get_ip_port();
        const std::uint8_t *pk = node->dht_public_key();
        dht_bootstrap(alice.get_dht(), &ip, pk);
        onion_add_bs_path_node(alice.get_onion_client(), &ip, pk);
    }

    Memory mem_struct = env.fake_memory().c_memory();
    const Memory *mem = &mem_struct;

    int total_decryption_failures = 0;
    std::set<std::array<std::uint8_t, CRYPTO_PUBLIC_KEY_SIZE>> seen_announcements;

    auto observer
        = [&](OnionNode *node, const std::vector<std::uint8_t> &data, const IP_Port &from) {
              if (data.empty())
                  return;
              // If it's an onion packet, it will be handled by Onion server.
              // We want to catch the final hop announce request.
              if (data[0] == 0x83 || data[0] == 0x87) {
                  // An announce request has 57 bytes of header and 120 bytes of ciphertext.
                  // There's also RETURN_3 appended, but we don't need it for decryption.
                  const std::size_t kHeaderSize = 1 + CRYPTO_NONCE_SIZE + CRYPTO_PUBLIC_KEY_SIZE;
                  const std::size_t kCiphertextSize = 120;

                  if (data.size() < kHeaderSize + kCiphertextSize)
                      return;

                  const std::uint8_t *nonce = data.data() + 1;
                  const std::uint8_t *sender_pk = data.data() + 1 + CRYPTO_NONCE_SIZE;
                  const std::uint8_t *ciphertext = sender_pk + CRYPTO_PUBLIC_KEY_SIZE;

                  std::vector<std::uint8_t> plain(kCiphertextSize - CRYPTO_MAC_SIZE);
                  int plen = decrypt_data(mem, sender_pk, node->dht_secret_key(), nonce, ciphertext,
                      kCiphertextSize, plain.data());

                  if (plen > 0) {
                      // The real PK (client_id) is in the payload at offset ONION_PING_ID_SIZE
                      // (32).
                      const std::uint8_t *real_pk = plain.data() + 32;
                      std::array<std::uint8_t, CRYPTO_PUBLIC_KEY_SIZE> real_pk_arr;
                      std::memcpy(real_pk_arr.data(), real_pk, CRYPTO_PUBLIC_KEY_SIZE);
                      seen_announcements.insert(real_pk_arr);
                  } else {
                      total_decryption_failures++;
#if 0
                fprintf(stderr, "Node %02x%02x... FAILED to decrypt announcement from %02x%02x... (size %zu)\n",
                       node->dht_public_key()[0], node->dht_public_key()[1], sender_pk[0],
                       sender_pk[1], data.size());
#endif
                  }
              }
          };

    bob.node().endpoint->set_recv_observer(
        [&](const std::vector<std::uint8_t> &data, const IP_Port &from) {
            observer(&bob, data, from);
        });
    charlie.node().endpoint->set_recv_observer(
        [&](const std::vector<std::uint8_t> &data, const IP_Port &from) {
            observer(&charlie, data, from);
        });
    dave.node().endpoint->set_recv_observer(
        [&](const std::vector<std::uint8_t> &data, const IP_Port &from) {
            observer(&dave, data, from);
        });

    // Give Alice time to connect.
    for (int i = 0; i < 30; ++i) {
        env.advance_time(500);
        alice.poll();
        for (auto node : nodes)
            node->poll();
        if (onion_connection_status(alice.get_onion_client()) != ONION_CONNECTION_STATUS_NONE) {
            break;
        }
    }

    ASSERT_NE(onion_connection_status(alice.get_onion_client()), ONION_CONNECTION_STATUS_NONE);

    const int kNumFriends = 2;
    std::vector<std::array<std::uint8_t, CRYPTO_PUBLIC_KEY_SIZE>> friend_pks;

    for (int i = 0; i < kNumFriends; ++i) {
        std::uint8_t pk[CRYPTO_PUBLIC_KEY_SIZE], sk[CRYPTO_SECRET_KEY_SIZE];
        crypto_new_keypair(alice.get_random(), pk, sk);
        onion_addfriend(alice.get_onion_client(), pk);
        std::array<std::uint8_t, CRYPTO_PUBLIC_KEY_SIZE> pk_arr;
        std::memcpy(pk_arr.data(), pk, CRYPTO_PUBLIC_KEY_SIZE);
        friend_pks.push_back(pk_arr);
    }

    // Wait for announcements.
    for (int i = 0; i < 20; ++i) {
        env.advance_time(1000);
        alice.poll();
        for (auto node : nodes)
            node->poll();

        // If we've seen most friends announced, we can stop early.
        int found_count = 0;
        for (const auto &pk : friend_pks) {
            if (seen_announcements.count(pk))
                found_count++;
        }
        if (found_count >= kNumFriends) {
            break;
        }
    }

    // On incorrect code, we expect many decryption failures because Alice reuses shared keys.
    // On correct code, there should be zero decryption failures.
    EXPECT_EQ(total_decryption_failures, 0) << "Decryption failed at the target node! This "
                                               "indicates Alice reused a shared key incorrectly.";

    int found_count = 0;
    for (const auto &pk : friend_pks) {
        if (seen_announcements.count(pk))
            found_count++;
    }
    EXPECT_GE(found_count, kNumFriends / 2)
        << "At least some friends should have been announced successfully.";
}

TEST_F(OnionClientTest, SharedKeyReuseOnEviction)
{
    OnionNode alice(env, 33445);

    // Alice adds a friend
    std::uint8_t friend_pk[CRYPTO_PUBLIC_KEY_SIZE];
    std::uint8_t friend_sk[CRYPTO_SECRET_KEY_SIZE];
    crypto_new_keypair(alice.get_random(), friend_pk, friend_sk);
    onion_addfriend(alice.get_onion_client(), friend_pk);

    // We use 20 nodes to ensure we fill the announcement list (size 12) and trigger evictions.
    std::vector<std::unique_ptr<OnionNode>> nodes;
    for (int i = 0; i < 20; ++i) {
        nodes.push_back(std::make_unique<OnionNode>(env, 33446 + i));
        IP_Port ip = nodes.back()->get_ip_port();
        onion_add_bs_path_node(alice.get_onion_client(), &ip, nodes.back()->dht_public_key());
    }

    // Make everyone know everyone via bootstrap
    for (auto &n1 : nodes) {
        // Bootstrap Alice to this node
        IP_Port ip1 = n1->get_ip_port();
        dht_bootstrap(alice.get_dht(), &ip1, n1->dht_public_key());

        for (auto &n2 : nodes) {
            if (n1 == n2)
                continue;
            IP_Port ip2 = n2->get_ip_port();
            dht_bootstrap(n1->get_dht(), &ip2, n2->dht_public_key());
        }
    }

    // Alice connects
    for (int i = 0; i < 20; ++i) {
        env.advance_time(500);
        alice.poll();
        for (auto &n : nodes)
            n->poll();
        if (onion_connection_status(alice.get_onion_client()) != ONION_CONNECTION_STATUS_NONE)
            break;
    }

    int total_decrypted = 0;
    int total_failed = 0;
    Memory mem_struct = env.fake_memory().c_memory();
    const Memory *mem = &mem_struct;

    auto observer = [&](OnionNode *node, const std::vector<std::uint8_t> &data) {
        if (data.size() < 1 + CRYPTO_NONCE_SIZE + CRYPTO_PUBLIC_KEY_SIZE)
            return;

        // Check for announce request (0x83 or 0x87)
        if (data[0] != 0x83 && data[0] != 0x87)
            return;

        const std::uint8_t *nonce = data.data() + 1;
        const std::uint8_t *sender_pk = data.data() + 1 + CRYPTO_NONCE_SIZE;

        const std::uint8_t *ciphertext = sender_pk + CRYPTO_PUBLIC_KEY_SIZE;
        // The announce request ciphertext is exactly 120 bytes.
        const std::size_t kCiphertextSize = 120;

        if (data.size() < (1 + CRYPTO_NONCE_SIZE + CRYPTO_PUBLIC_KEY_SIZE + kCiphertextSize))
            return;

        std::vector<std::uint8_t> plain(kCiphertextSize - CRYPTO_MAC_SIZE);
        int plen = decrypt_data(mem, sender_pk, node->dht_secret_key(), nonce, ciphertext,
            kCiphertextSize, plain.data());

        if (plen > 0) {
            total_decrypted++;
        } else {
            total_failed++;
        }
    };

    for (auto &n : nodes) {
        n->node().endpoint->set_recv_observer(
            [&, ptr = n.get()](const std::vector<std::uint8_t> &data, const IP_Port &from) {
                observer(ptr, data);
            });
    }

    // Run for a while to ensure many announcements are sent and some slots are reused.
    for (int i = 0; i < 30; ++i) {
        env.advance_time(1000);
        alice.poll();
        for (auto &n : nodes)
            n->poll();
    }

    EXPECT_GT(total_decrypted, 0);
    EXPECT_EQ(total_failed, 0)
        << "Decryption failed! This indicates Alice reused a shared key incorrectly after a node "
           "slot was evicted and replaced.";
}

}  // namespace
