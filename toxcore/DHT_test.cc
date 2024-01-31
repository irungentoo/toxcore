#include "DHT.h"

#include <gmock/gmock.h>
#include <gtest/gtest.h>

#include <algorithm>
#include <array>
#include <cstring>
#include <random>

#include "DHT_test_util.hh"
#include "crypto_core.h"
#include "crypto_core_test_util.hh"
#include "logger.h"
#include "mem_test_util.hh"
#include "mono_time.h"
#include "network.h"
#include "network_test_util.hh"
#include "test_util.hh"

namespace {

using ::testing::Each;
using ::testing::ElementsAre;
using ::testing::Eq;
using ::testing::PrintToString;
using ::testing::UnorderedElementsAre;

using SecretKey = std::array<uint8_t, CRYPTO_SECRET_KEY_SIZE>;

struct KeyPair {
    PublicKey pk;
    SecretKey sk;

    explicit KeyPair(const Random *rng) { crypto_new_keypair(rng, pk.data(), sk.data()); }
};

TEST(IdClosest, KeyIsClosestToItself)
{
    Test_Random rng;

    PublicKey pk0 = random_pk(rng);
    PublicKey pk1;
    do {
        // Get a random key that's not the same as pk0.
        pk1 = random_pk(rng);
    } while (pk0 == pk1);

    EXPECT_EQ(id_closest(pk0.data(), pk0.data(), pk1.data()), 1);
}

TEST(IdClosest, IdenticalKeysAreSameDistance)
{
    Test_Random rng;

    PublicKey pk0 = random_pk(rng);
    PublicKey pk1 = random_pk(rng);

    EXPECT_EQ(id_closest(pk0.data(), pk1.data(), pk1.data()), 0);
}

TEST(IdClosest, DistanceIsCommutative)
{
    Test_Random rng;

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

TEST(IdClosest, SmallXorDistanceIsCloser)
{
    PublicKey const pk0 = {0xaa};
    PublicKey const pk1 = {0xa0};
    PublicKey const pk2 = {0x0a};

    EXPECT_EQ(id_closest(pk0.data(), pk1.data(), pk2.data()), 1);
}

TEST(IdClosest, DistinctKeysCannotHaveTheSameDistance)
{
    PublicKey const pk0 = {0x06};
    PublicKey const pk1 = {0x00};
    PublicKey pk2 = {0x00};

    for (uint8_t i = 1; i < 0xff; ++i) {
        pk2[0] = i;
        EXPECT_NE(id_closest(pk0.data(), pk1.data(), pk2.data()), 0);
    }
}

TEST(AddToList, OverridesKeysWithCloserKeys)
{
    PublicKey const self_pk = {0xaa};
    PublicKey const keys[] = {
        {0xa0},  // closest
        {0x0a},  //
        {0x0b},  //
        {0x0c},  //
        {0x0d},  //
        {0xa1},  // closer than the 4 keys above
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

Node_format fill(Node_format v, PublicKey const &pk, IP_Port const &ip_port)
{
    std::copy(pk.begin(), pk.end(), v.public_key);
    v.ip_port = ip_port;
    return v;
}

TEST(AddToList, AddsFirstKeysInOrder)
{
    Test_Random rng;

    // Make cmp_key the furthest away from 00000... as possible, so all initial inserts succeed.
    PublicKey const cmp_pk{0xff, 0xff, 0xff, 0xff};

    // Generate a bunch of other keys, sorted by distance from cmp_pk.
    auto const keys
        = sorted(array_of<20>(random_pk, rng), [&cmp_pk](auto const &pk1, auto const &pk2) {
              return id_closest(cmp_pk.data(), pk1.data(), pk2.data()) == 1;
          });
    auto const ips = array_of<20>(increasing_ip_port(0, rng));

    std::vector<Node_format> nodes(4);

    // Add a bunch of nodes.
    ASSERT_TRUE(add_to_list(nodes.data(), nodes.size(), keys[2].data(), &ips[2], cmp_pk.data()))
        << "failed to insert\n"
        << "  cmp_pk = " << cmp_pk << "\n"
        << "  pk     = " << keys[2] << "\n"
        << "  nodes_list = " << PrintToString(nodes);
    ASSERT_TRUE(add_to_list(nodes.data(), nodes.size(), keys[5].data(), &ips[5], cmp_pk.data()))
        << "failed to insert\n"
        << "  cmp_pk = " << cmp_pk << "\n"
        << "  pk     = " << keys[5] << "\n"
        << "  nodes_list = " << PrintToString(nodes);
    ASSERT_TRUE(add_to_list(nodes.data(), nodes.size(), keys[7].data(), &ips[7], cmp_pk.data()))
        << "failed to insert\n"
        << "  cmp_pk = " << cmp_pk << "\n"
        << "  pk     = " << keys[7] << "\n"
        << "  nodes_list = " << PrintToString(nodes);
    ASSERT_TRUE(add_to_list(nodes.data(), nodes.size(), keys[9].data(), &ips[9], cmp_pk.data()))
        << "failed to insert\n"
        << "  cmp_pk = " << cmp_pk << "\n"
        << "  pk     = " << keys[9] << "\n"
        << "  nodes_list = " << PrintToString(nodes);

    // They should all appear in order.
    EXPECT_THAT(nodes,
        ElementsAre(  //
            fill(Node_format{}, keys[2], ips[2]),  //
            fill(Node_format{}, keys[5], ips[5]),  //
            fill(Node_format{}, keys[7], ips[7]),  //
            fill(Node_format{}, keys[9], ips[9])));

    // Adding another node that's further away will not happen.
    ASSERT_FALSE(add_to_list(nodes.data(), nodes.size(), keys[10].data(), &ips[10], cmp_pk.data()))
        << "incorrectly inserted\n"
        << "  cmp_pk = " << cmp_pk << "\n"
        << "  pk     = " << keys[10] << "\n"
        << "  nodes_list = " << PrintToString(nodes);

    // Now shuffle each time we add a node, which should work fine.
    std::mt19937 mt_rng;

    // Adding one that's closer will happen.
    std::shuffle(nodes.begin(), nodes.end(), mt_rng);
    ASSERT_TRUE(add_to_list(nodes.data(), nodes.size(), keys[8].data(), &ips[8], cmp_pk.data()))
        << "failed to insert\n"
        << "  cmp_pk = " << cmp_pk << "\n"
        << "  pk     = " << keys[8] << "\n"
        << "  nodes_list = " << PrintToString(nodes);

    EXPECT_THAT(nodes,
        UnorderedElementsAre(  //
            fill(Node_format{}, keys[2], ips[2]),  //
            fill(Node_format{}, keys[5], ips[5]),  //
            fill(Node_format{}, keys[7], ips[7]),  //
            fill(Node_format{}, keys[8], ips[8])));

    // Adding one that's closer than almost all of them will happen.
    std::shuffle(nodes.begin(), nodes.end(), mt_rng);
    ASSERT_TRUE(add_to_list(nodes.data(), nodes.size(), keys[4].data(), &ips[4], cmp_pk.data()))
        << "failed to insert\n"
        << "  cmp_pk = " << cmp_pk << "\n"
        << "  pk     = " << keys[4] << "\n"
        << "  nodes_list = " << PrintToString(nodes);

    EXPECT_THAT(nodes,
        UnorderedElementsAre(  //
            fill(Node_format{}, keys[2], ips[2]),  //
            fill(Node_format{}, keys[4], ips[4]),  //
            fill(Node_format{}, keys[5], ips[5]),  //
            fill(Node_format{}, keys[7], ips[7])));

    // Adding one that's closer than all of them will happen.
    std::shuffle(nodes.begin(), nodes.end(), mt_rng);
    ASSERT_TRUE(add_to_list(nodes.data(), nodes.size(), keys[1].data(), &ips[1], cmp_pk.data()))
        << "failed to insert\n"
        << "  cmp_pk = " << cmp_pk << "\n"
        << "  pk     = " << keys[1] << "\n"
        << "  nodes_list = " << PrintToString(nodes);

    EXPECT_THAT(nodes,
        UnorderedElementsAre(  //
            fill(Node_format{}, keys[1], ips[1]),  //
            fill(Node_format{}, keys[2], ips[2]),  //
            fill(Node_format{}, keys[4], ips[4]),  //
            fill(Node_format{}, keys[5], ips[5])));
}

TEST(AddToList, KeepsKeysInOrder)
{
    Test_Random rng;

    // Any random cmp_pk should work, as well as the smallest or (approximately) largest pk.
    for (PublicKey const cmp_pk : {random_pk(rng), PublicKey{0x00}, PublicKey{0xff, 0xff}}) {
        auto const by_distance = [&cmp_pk](auto const &node1, auto const &node2) {
            return id_closest(cmp_pk.data(), node1.public_key, node2.public_key) == 1;
        };

        // Generate a bunch of other keys, not sorted.
        auto const nodes = vector_of(16, random_node_format, rng);

        std::vector<Node_format> node_list(4);

        // Add all of them.
        for (Node_format const &node : nodes) {
            add_to_list(
                node_list.data(), node_list.size(), node.public_key, &node.ip_port, cmp_pk.data());
            // Nodes should always be sorted.
            EXPECT_THAT(node_list, Eq(sorted(node_list, by_distance)));
        }
    }
}

TEST(Request, CreateAndParse)
{
    Test_Random rng;

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
    Test_Random rng;
    Test_Memory mem;
    Test_Network ns;

    Logger *log = logger_new();
    ASSERT_NE(log, nullptr);
    Mono_Time *mono_time = mono_time_new(mem, nullptr, nullptr);
    ASSERT_NE(mono_time, nullptr);
    Ptr<Networking_Core> net(new_networking_no_udp(log, mem, ns));
    ASSERT_NE(net, nullptr);
    Ptr<DHT> dht(new_dht(log, mem, rng, ns, mono_time, net.get(), true, true));
    ASSERT_NE(dht, nullptr);

    uint8_t pk_data[CRYPTO_PUBLIC_KEY_SIZE];
    memcpy(pk_data, dht_get_self_public_key(dht.get()), sizeof(pk_data));
    PublicKey self_pk(to_array(pk_data));

    PublicKey pk1 = random_pk(rng);
    ASSERT_NE(pk1, self_pk);

    // Test with maximally close key to self
    pk_data[CRYPTO_PUBLIC_KEY_SIZE - 1] = ~pk_data[CRYPTO_PUBLIC_KEY_SIZE - 1];
    PublicKey pk2(to_array(pk_data));
    ASSERT_NE(pk2, pk1);

    IP_Port ip_port = {0};
    ip_port.ip.family = net_family_ipv4();

    set_announce_node(dht.get(), pk1.data());
    set_announce_node(dht.get(), pk2.data());

    EXPECT_TRUE(addto_lists(dht.get(), &ip_port, pk1.data()));
    EXPECT_TRUE(addto_lists(dht.get(), &ip_port, pk2.data()));

    Node_format nodes[MAX_SENT_NODES];
    EXPECT_EQ(
        0, get_close_nodes(dht.get(), self_pk.data(), nodes, net_family_unspec(), true, true));
    set_announce_node(dht.get(), pk1.data());
    set_announce_node(dht.get(), pk2.data());
    EXPECT_EQ(
        2, get_close_nodes(dht.get(), self_pk.data(), nodes, net_family_unspec(), true, true));

    mono_time_free(mem, mono_time);
    logger_kill(log);
}

}  // namespace
