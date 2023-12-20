#include "DHT.h"

#include <gtest/gtest.h>

#include <algorithm>
#include <array>

#include "crypto_core.h"

namespace {

using PublicKey = std::array<uint8_t, CRYPTO_PUBLIC_KEY_SIZE>;
using SecretKey = std::array<uint8_t, CRYPTO_SECRET_KEY_SIZE>;

struct KeyPair {
    PublicKey pk;
    SecretKey sk;

    explicit KeyPair(const Random *rng) { crypto_new_keypair(rng, pk.data(), sk.data()); }
};

template <typename T, size_t N>
std::array<T, N> to_array(T const (&arr)[N])
{
    std::array<T, N> stdarr;
    std::copy(arr, arr + N, stdarr.begin());
    return stdarr;
}

PublicKey random_pk(const Random *rng)
{
    PublicKey pk;
    random_bytes(rng, pk.data(), pk.size());
    return pk;
}

TEST(IdClosest, IdenticalKeysAreSameDistance)
{
    const Random *rng = system_random();
    ASSERT_NE(rng, nullptr);

    PublicKey pk0 = random_pk(rng);
    PublicKey pk1 = random_pk(rng);
    PublicKey pk2 = pk1;

    EXPECT_EQ(id_closest(pk0.data(), pk1.data(), pk2.data()), 0);
}

TEST(IdClosest, DistanceIsCommutative)
{
    const Random *rng = system_random();
    ASSERT_NE(rng, nullptr);

    for (uint32_t i = 0; i < 100; ++i) {
        PublicKey pk0 = random_pk(rng);
        PublicKey pk1 = random_pk(rng);
        PublicKey pk2 = random_pk(rng);

        ASSERT_NE(pk1, pk2);  // RNG can't produce the same random key twice

        // Two non-equal keys can't have the same distance from any given key.
        EXPECT_NE(id_closest(pk0.data(), pk1.data(), pk2.data()), 0);

        if (id_closest(pk0.data(), pk1.data(), pk2.data()) == 1) {
            EXPECT_EQ(id_closest(pk0.data(), pk2.data(), pk1.data()), 2);
        }

        if (id_closest(pk0.data(), pk1.data(), pk2.data()) == 2) {
            EXPECT_EQ(id_closest(pk0.data(), pk2.data(), pk1.data()), 1);
        }
    }
}

TEST(IdClosest, SmallXorDistanceIsCloser)
{
    PublicKey const pk0 = {{0xaa}};
    PublicKey const pk1 = {{0xa0}};
    PublicKey const pk2 = {{0x0a}};

    EXPECT_EQ(id_closest(pk0.data(), pk1.data(), pk2.data()), 1);
}

TEST(IdClosest, DistinctKeysCannotHaveTheSameDistance)
{
    PublicKey const pk0 = {{0x06}};
    PublicKey const pk1 = {{0x00}};
    PublicKey pk2 = {{0x00}};

    for (uint8_t i = 1; i < 0xff; ++i) {
        pk2[0] = i;
        EXPECT_NE(id_closest(pk0.data(), pk1.data(), pk2.data()), 0);
    }
}

TEST(AddToList, OverridesKeysWithCloserKeys)
{
    PublicKey const self_pk = {{0xaa}};
    PublicKey const keys[] = {
        {{0xa0}},  // closest
        {{0x0a}},  //
        {{0x0b}},  //
        {{0x0c}},  //
        {{0x0d}},  //
        {{0xa1}},  // closer than the 4 keys above
    };

    std::array<Node_format, 4> nodes{};

    IP_Port ip_port = {0};
    EXPECT_TRUE(add_to_list(nodes.data(), nodes.size(), keys[0].data(), &ip_port, self_pk.data()));
    EXPECT_TRUE(add_to_list(nodes.data(), nodes.size(), keys[1].data(), &ip_port, self_pk.data()));
    EXPECT_TRUE(add_to_list(nodes.data(), nodes.size(), keys[2].data(), &ip_port, self_pk.data()));
    EXPECT_TRUE(add_to_list(nodes.data(), nodes.size(), keys[3].data(), &ip_port, self_pk.data()));

    EXPECT_EQ(to_array(nodes[0].public_key), keys[0]);
    EXPECT_EQ(to_array(nodes[1].public_key), keys[1]);
    EXPECT_EQ(to_array(nodes[2].public_key), keys[2]);
    EXPECT_EQ(to_array(nodes[3].public_key), keys[3]);

    // key 4 is less close than keys 0-3
    EXPECT_FALSE(add_to_list(nodes.data(), nodes.size(), keys[4].data(), &ip_port, self_pk.data()));
    // 5 is closer than all except key 0
    EXPECT_TRUE(add_to_list(nodes.data(), nodes.size(), keys[5].data(), &ip_port, self_pk.data()));

    EXPECT_EQ(to_array(nodes[0].public_key), keys[0]);
    EXPECT_EQ(to_array(nodes[1].public_key), keys[5]);
    EXPECT_EQ(to_array(nodes[2].public_key), keys[1]);
    EXPECT_EQ(to_array(nodes[3].public_key), keys[2]);
}

TEST(Request, CreateAndParse)
{
    const Random *rng = system_random();
    ASSERT_NE(rng, nullptr);

    // Peers.
    const KeyPair sender(rng);
    const KeyPair receiver(rng);
    const uint8_t sent_pkt_id = CRYPTO_PACKET_FRIEND_REQ;

    // Encoded packet.
    std::array<uint8_t, MAX_CRYPTO_REQUEST_SIZE> packet;

    // Received components.
    PublicKey pk;
    std::array<uint8_t, MAX_CRYPTO_REQUEST_SIZE> incoming;
    uint8_t recvd_pkt_id;

    // Request data: maximum payload is 918 bytes, so create a payload 1 byte larger than max.
    std::vector<uint8_t> outgoing(919);
    random_bytes(rng, outgoing.data(), outgoing.size());

    EXPECT_LT(create_request(rng, sender.pk.data(), sender.sk.data(), packet.data(),
                  receiver.pk.data(), outgoing.data(), outgoing.size(), sent_pkt_id),
        0);

    // Pop one element so the payload is 918 bytes. Packing should now succeed.
    outgoing.pop_back();

    const int max_sent_length = create_request(rng, sender.pk.data(), sender.sk.data(),
        packet.data(), receiver.pk.data(), outgoing.data(), outgoing.size(), sent_pkt_id);
    ASSERT_GT(max_sent_length, 0);  // success.

    // Check that handle_request rejects packets larger than the maximum created packet size.
    EXPECT_LT(handle_request(receiver.pk.data(), receiver.sk.data(), pk.data(), incoming.data(),
                  &recvd_pkt_id, packet.data(), max_sent_length + 1),
        0);

    // Now try all possible packet sizes from max (918) to 0.
    while (!outgoing.empty()) {
        // Pack:
        const int sent_length = create_request(rng, sender.pk.data(), sender.sk.data(),
            packet.data(), receiver.pk.data(), outgoing.data(), outgoing.size(), sent_pkt_id);
        ASSERT_GT(sent_length, 0);

        // Unpack:
        const int recvd_length = handle_request(receiver.pk.data(), receiver.sk.data(), pk.data(),
            incoming.data(), &recvd_pkt_id, packet.data(), sent_length);
        ASSERT_GE(recvd_length, 0);

        EXPECT_EQ(
            std::vector<uint8_t>(incoming.begin(), incoming.begin() + recvd_length), outgoing);

        outgoing.pop_back();
    }
}

TEST(AnnounceNodes, SetAndTest)
{
    const Random *rng = system_random();
    const Network *ns = system_network();
    const Memory *mem = system_memory();

    Logger *log = logger_new();
    ASSERT_NE(log, nullptr);
    Mono_Time *mono_time = mono_time_new(mem, nullptr, nullptr);
    ASSERT_NE(mono_time, nullptr);
    Networking_Core *net = new_networking_no_udp(log, mem, ns);
    ASSERT_NE(net, nullptr);
    DHT *dht = new_dht(log, mem, rng, ns, mono_time, net, true, true);
    ASSERT_NE(dht, nullptr);

    uint8_t pk_data[CRYPTO_PUBLIC_KEY_SIZE];
    memcpy(pk_data, dht_get_self_public_key(dht), sizeof(pk_data));
    PublicKey self_pk = to_array(pk_data);

    PublicKey pk1 = random_pk(rng);
    ASSERT_NE(pk1, self_pk);

    // Test with maximally close key to self
    pk_data[CRYPTO_PUBLIC_KEY_SIZE - 1] = ~pk_data[CRYPTO_PUBLIC_KEY_SIZE - 1];
    PublicKey pk2 = to_array(pk_data);
    ASSERT_NE(pk2, pk1);

    IP_Port ip_port = {0};
    ip_port.ip.family = net_family_ipv4();

    set_announce_node(dht, pk1.data());
    set_announce_node(dht, pk2.data());

    EXPECT_TRUE(addto_lists(dht, &ip_port, pk1.data()));
    EXPECT_TRUE(addto_lists(dht, &ip_port, pk2.data()));

    Node_format nodes[MAX_SENT_NODES];
    EXPECT_EQ(0, get_close_nodes(dht, self_pk.data(), nodes, net_family_unspec(), true, true));
    set_announce_node(dht, pk1.data());
    set_announce_node(dht, pk2.data());
    EXPECT_EQ(2, get_close_nodes(dht, self_pk.data(), nodes, net_family_unspec(), true, true));

    kill_dht(dht);
    kill_networking(net);
    mono_time_free(mem, mono_time);
    logger_kill(log);
}

}  // namespace
