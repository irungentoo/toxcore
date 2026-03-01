#include "onion_client.h"

#include <algorithm>
#include <cstddef>
#include <cstring>
#include <map>
#include <memory>
#include <vector>

#include "../testing/support/doubles/fake_sockets.hh"
#include "../testing/support/public/fuzz_data.hh"
#include "../testing/support/public/simulated_environment.hh"
#include "DHT.h"
#include "attributes.h"
#include "net_crypto.h"
#include "net_profile.h"
#include "network.h"
#include "test_util.hh"

namespace {

using tox::test::FakeUdpSocket;
using tox::test::Fuzz_Data;
using tox::test::SimulatedEnvironment;

template <typename T>
T consume_range(Fuzz_Data &input, T min, T max)
{
    T val = input.consume_integral<T>();
    if (max <= min)
        return min;
    return min + (val % (max - min + 1));
}

// Minimal DHT wrapper for fuzzing
class FuzzDHT {
public:
    FuzzDHT(SimulatedEnvironment &env, std::uint16_t port)
        : node_(env.create_node(port))
        , logger_(logger_new(&node_->c_memory), [](Logger *l) { logger_kill(l); })
        , mono_time_(mono_time_new(
                         &node_->c_memory,
                         [](void *ud) -> std::uint64_t {
                             return static_cast<tox::test::FakeClock *>(ud)->current_time_ms();
                         },
                         &env.fake_clock()),
              [mem = &node_->c_memory](Mono_Time *t) { mono_time_free(mem, t); })
        , networking_(nullptr, [](Networking_Core *n) { kill_networking(n); })
        , dht_(nullptr, [](DHT *d) { kill_dht(d); })
    {
        IP ip;
        ip_init(&ip, true);
        unsigned int error = 0;
        networking_.reset(new_networking_ex(
            logger_.get(), &node_->c_memory, &node_->c_network, &ip, port, port + 1, &error));
        // In fuzzing we might ignore assert, but setup should succeed
        node_->endpoint = node_->node->get_primary_socket();

        dht_.reset(new_dht(logger_.get(), &node_->c_memory, &node_->c_random, &node_->c_network,
            mono_time_.get(), networking_.get(), true, true));
    }

    DHT *_Nonnull get_dht() { return REQUIRE_NOT_NULL(dht_.get()); }
    Networking_Core *_Nonnull networking() { return REQUIRE_NOT_NULL(networking_.get()); }
    Mono_Time *_Nonnull mono_time() { return REQUIRE_NOT_NULL(mono_time_.get()); }
    Logger *_Nonnull logger() { return REQUIRE_NOT_NULL(logger_.get()); }
    tox::test::ScopedToxSystem &node() { return *node_; }
    FakeUdpSocket *_Nullable endpoint() { return node_->endpoint; }

    static const Net_Crypto_DHT_Funcs funcs;

private:
    std::unique_ptr<tox::test::ScopedToxSystem> node_;
    std::unique_ptr<Logger, void (*)(Logger *)> logger_;
    std::unique_ptr<Mono_Time, std::function<void(Mono_Time *)>> mono_time_;
    std::unique_ptr<Networking_Core, void (*)(Networking_Core *)> networking_;
    std::unique_ptr<DHT, void (*)(DHT *)> dht_;
};

const Net_Crypto_DHT_Funcs FuzzDHT::funcs = {
    [](void *_Nonnull obj, const std::uint8_t *_Nonnull public_key) {
        return dht_get_shared_key_sent(static_cast<DHT *>(obj), public_key);
    },
    [](const void *_Nonnull obj) { return dht_get_self_public_key(static_cast<const DHT *>(obj)); },
    [](const void *_Nonnull obj) { return dht_get_self_secret_key(static_cast<const DHT *>(obj)); },
};

class OnionClientFuzzer {
public:
    OnionClientFuzzer(SimulatedEnvironment &env)
        : env_(env)
        , dht_(env, 33445)
        , net_profile_(netprof_new(dht_.logger(), &dht_.node().c_memory),
              [mem = &dht_.node().c_memory](Net_Profile *p) { netprof_kill(mem, p); })
        , net_crypto_(nullptr, [](Net_Crypto *c) { kill_net_crypto(c); })
        , onion_client_(nullptr, [](Onion_Client *c) { kill_onion_client(c); })
    {
        TCP_Proxy_Info proxy_info = {{0}, TCP_PROXY_NONE};
        net_crypto_.reset(new_net_crypto(dht_.logger(), &dht_.node().c_memory,
            &dht_.node().c_random, &dht_.node().c_network, dht_.mono_time(), dht_.networking(),
            dht_.get_dht(), &FuzzDHT::funcs, &proxy_info, net_profile_.get()));

        onion_client_.reset(
            new_onion_client(dht_.logger(), &dht_.node().c_memory, &dht_.node().c_random,
                dht_.mono_time(), net_crypto_.get(), dht_.get_dht(), dht_.networking()));

        // Register a handler for onion data to verify reception
        oniondata_registerhandler(
            onion_client_.get(), 0,
            [](void *, const std::uint8_t *, const std::uint8_t *, std::uint16_t, void *) {
                // Callback hit
                return 0;
            },
            nullptr);
    }

    void Run(Fuzz_Data &input)
    {
        while (!input.empty()) {
            Action(input);
            // Always pump the loop
            do_onion_client(onion_client_.get());
            networking_poll(dht_.networking(), nullptr);
        }
    }

private:
    void Action(Fuzz_Data &input)
    {
        std::uint8_t op = input.consume_integral<std::uint8_t>();
        switch (op % 12) {
        case 0:
            AddFriend(input);
            break;
        case 1:
            DelFriend(input);
            break;
        case 2:
            SetOnline(input);
            break;
        case 3:
            SetDHTKey(input);
            break;
        case 4:
            AddBSNode(input);
            break;
        case 5:
            ReceivePacket(input);
            break;
        case 6:
            AdvanceTime(input);
            break;
        case 7:
            SendData(input);
            break;
        case 8:
            GetFriendIP(input);
            break;
        case 9:
            BackupNodes(input);
            break;
        case 10:
            CheckStatus();
            break;
        case 11:
            SetFriendTCPRelay(input);
            break;
        }
    }

    void AddFriend(Fuzz_Data &input)
    {
        std::uint8_t pk[CRYPTO_PUBLIC_KEY_SIZE];
        std::uint8_t sk[CRYPTO_SECRET_KEY_SIZE];
        crypto_new_keypair(&dht_.node().c_random, pk, sk);

        int friend_num = onion_addfriend(onion_client_.get(), pk);
        if (friend_num != -1) {
            friends_.push_back(friend_num);
            friend_keys_[friend_num] = {std::vector<std::uint8_t>(pk, pk + CRYPTO_PUBLIC_KEY_SIZE),
                std::vector<std::uint8_t>(sk, sk + CRYPTO_SECRET_KEY_SIZE)};
        }
    }

    void DelFriend(Fuzz_Data &input)
    {
        if (friends_.empty())
            return;
        std::size_t idx = consume_range<std::size_t>(input, 0, friends_.size() - 1);
        int friend_num = friends_[idx];
        onion_delfriend(onion_client_.get(), friend_num);
        friends_.erase(friends_.begin() + idx);
        friend_keys_.erase(friend_num);
    }

    void SetOnline(Fuzz_Data &input)
    {
        if (friends_.empty())
            return;
        int friend_num = friends_[consume_range<std::size_t>(input, 0, friends_.size() - 1)];
        bool online = input.consume_integral<bool>();
        onion_set_friend_online(onion_client_.get(), friend_num, online);
    }

    void SetDHTKey(Fuzz_Data &input)
    {
        if (friends_.empty())
            return;
        int friend_num = friends_[consume_range<std::size_t>(input, 0, friends_.size() - 1)];
        CONSUME_OR_RETURN(const std::uint8_t *pk, input, CRYPTO_PUBLIC_KEY_SIZE);
        onion_set_friend_dht_pubkey(onion_client_.get(), friend_num, pk);
    }

    void AddBSNode(Fuzz_Data &input)
    {
        IP_Port ip_port;
        ip_init(&ip_port.ip, 1);
        ip_port.port = input.consume_integral<std::uint16_t>();
        CONSUME_OR_RETURN(const std::uint8_t *pk, input, CRYPTO_PUBLIC_KEY_SIZE);
        onion_add_bs_path_node(onion_client_.get(), &ip_port, pk);
    }

    void ReceivePacket(Fuzz_Data &input)
    {
        if (input.remaining_bytes() < 1)
            return;

        std::vector<std::uint8_t> packet;
        std::uint8_t type = input.consume_integral<std::uint8_t>();

        if (type < 50) {
            std::size_t size = consume_range<std::size_t>(input, 10, 500);
            if (input.remaining_bytes() >= size) {
                const std::uint8_t *ptr = input.consume("ReceivePacket", size);
                if (ptr)
                    packet.assign(ptr, ptr + size);
            }
        } else if (type >= 50 && type < 150) {
            // Generate valid NET_PACKET_ANNOUNCE_RESPONSE
            std::uint8_t secret_key[CRYPTO_SYMMETRIC_KEY_SIZE];
            onion_testonly_get_secret_symmetric_key(onion_client_.get(), secret_key);

            std::uint8_t nonce[CRYPTO_NONCE_SIZE];
            random_bytes(&dht_.node().c_random, nonce, sizeof(nonce));

            std::size_t data_len = consume_range<std::size_t>(input, 1, 100);
            std::vector<std::uint8_t> plaintext = input.consume_bytes(data_len);
            if (plaintext.empty())
                plaintext = {1, 2, 3};  // fallback

            std::vector<std::uint8_t> ciphertext(plaintext.size() + CRYPTO_MAC_SIZE);
            int len = encrypt_data_symmetric(&dht_.node().c_memory, secret_key, nonce,
                plaintext.data(), plaintext.size(), ciphertext.data());

            if (len != -1) {
                packet.push_back(NET_PACKET_ANNOUNCE_RESPONSE);
                packet.insert(packet.end(), nonce, nonce + CRYPTO_NONCE_SIZE);
                packet.insert(packet.end(), ciphertext.begin(), ciphertext.end());
            }

        } else if (type >= 150 && !friends_.empty()) {
            // Valid onion data response injection
            int friend_num = friends_[consume_range<std::size_t>(input, 0, friends_.size() - 1)];
            const auto &keys = friend_keys_[friend_num];

            std::uint8_t sender_temp_pk[CRYPTO_PUBLIC_KEY_SIZE];
            std::uint8_t sender_temp_sk[CRYPTO_SECRET_KEY_SIZE];
            crypto_new_keypair(&dht_.node().c_random, sender_temp_pk, sender_temp_sk);

            std::uint8_t nonce[CRYPTO_NONCE_SIZE];
            random_bytes(&dht_.node().c_random, nonce, sizeof(nonce));

            // Inner packet - Let fuzzer choose type
            std::uint8_t inner_type = input.consume_integral<std::uint8_t>();
            std::vector<std::uint8_t> inner_data = {inner_type};

            std::size_t data_len = consume_range<std::size_t>(input, 1, 100);
            std::vector<std::uint8_t> rand_data = input.consume_bytes(data_len);
            inner_data.insert(inner_data.end(), rand_data.begin(), rand_data.end());

            std::vector<std::uint8_t> inner_ciphertext(inner_data.size() + CRYPTO_MAC_SIZE);
            int len = encrypt_data(&dht_.node().c_memory, dht_get_self_public_key(dht_.get_dht()),
                keys.second.data(), nonce, inner_data.data(), inner_data.size(),
                inner_ciphertext.data());
            if (len == -1)
                return;

            // Outer packet content: Sender Real PK + Inner Ciphertext
            std::vector<std::uint8_t> outer_plaintext(
                CRYPTO_PUBLIC_KEY_SIZE + inner_ciphertext.size());
            std::memcpy(outer_plaintext.data(), keys.first.data(), CRYPTO_PUBLIC_KEY_SIZE);
            std::memcpy(outer_plaintext.data() + CRYPTO_PUBLIC_KEY_SIZE, inner_ciphertext.data(),
                inner_ciphertext.size());

            std::uint8_t receiver_temp_pk[CRYPTO_PUBLIC_KEY_SIZE];
            onion_testonly_get_temp_public_key(onion_client_.get(), receiver_temp_pk);

            std::vector<std::uint8_t> outer_ciphertext(outer_plaintext.size() + CRYPTO_MAC_SIZE);
            len = encrypt_data(&dht_.node().c_memory, receiver_temp_pk, sender_temp_sk, nonce,
                outer_plaintext.data(), outer_plaintext.size(), outer_ciphertext.data());
            if (len == -1)
                return;

            // Final packet: Type + Nonce + Sender Temp PK + Outer Ciphertext
            packet.push_back(NET_PACKET_ONION_DATA_RESPONSE);
            packet.insert(packet.end(), nonce, nonce + CRYPTO_NONCE_SIZE);
            packet.insert(packet.end(), sender_temp_pk, sender_temp_pk + CRYPTO_PUBLIC_KEY_SIZE);
            packet.insert(packet.end(), outer_ciphertext.begin(), outer_ciphertext.end());
        } else {
            packet = input.consume_remaining_bytes();
        }

        if (packet.empty())
            return;

        IP_Port from;
        ip_init(&from.ip, 1);  // loopback
        from.port = 12345;  // arbitrary

        dht_.endpoint()->push_packet(packet, from);
    }

    void AdvanceTime(Fuzz_Data &input)
    {
        std::uint32_t ms = input.consume_integral_in_range<std::uint32_t>(1, 10000);
        env_.fake_clock().advance(ms);
    }

    void SendData(Fuzz_Data &input)
    {
        if (friends_.empty())
            return;
        int friend_num = friends_[consume_range<std::size_t>(input, 0, friends_.size() - 1)];

        std::uint16_t length = consume_range<std::uint16_t>(input, 1, 1024);
        if (input.remaining_bytes() >= length) {
            const std::uint8_t *ptr = input.consume("SendData", length);
            if (ptr)
                send_onion_data(onion_client_.get(), friend_num, ptr, length);
        }
    }

    void GetFriendIP(Fuzz_Data &input)
    {
        if (friends_.empty())
            return;
        int friend_num = friends_[consume_range<std::size_t>(input, 0, friends_.size() - 1)];
        IP_Port ip_port;
        onion_getfriendip(onion_client_.get(), friend_num, &ip_port);
    }

    void BackupNodes(Fuzz_Data &input)
    {
        Node_format nodes[10];
        onion_backup_nodes(onion_client_.get(), nodes, 10);
    }

    void CheckStatus() { onion_connection_status(onion_client_.get()); }

    void SetFriendTCPRelay(Fuzz_Data &input)
    {
        if (friends_.empty())
            return;
        int friend_num
            = friends_[input.consume_integral_in_range<std::size_t>(0, friends_.size() - 1)];
        // Just setting a dummy callback
        recv_tcp_relay_handler(
            onion_client_.get(), friend_num,
            [](void *, std::uint32_t, const IP_Port *, const std::uint8_t *) { return 0; }, this,
            0);
    }

    SimulatedEnvironment &env_;
    FuzzDHT dht_;
    std::unique_ptr<Net_Profile, std::function<void(Net_Profile *)>> net_profile_;
    std::unique_ptr<Net_Crypto, void (*)(Net_Crypto *)> net_crypto_;
    std::unique_ptr<Onion_Client, void (*)(Onion_Client *)> onion_client_;
    std::vector<int> friends_;
    std::map<int, std::pair<std::vector<std::uint8_t>, std::vector<std::uint8_t>>> friend_keys_;
};

}  // namespace

extern "C" int LLVMFuzzerTestOneInput(const std::uint8_t *data, std::size_t size);
extern "C" int LLVMFuzzerTestOneInput(const std::uint8_t *data, std::size_t size)
{
    if (size == 0)
        return 0;

    SimulatedEnvironment env{12345};
    OnionClientFuzzer fuzzer(env);
    Fuzz_Data input(data, size);
    fuzzer.Run(input);

    return 0;
}
