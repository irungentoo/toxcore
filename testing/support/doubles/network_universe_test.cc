#include "network_universe.hh"

#include <gtest/gtest.h>

#include <cstddef>

#include "fake_sockets.hh"

namespace tox::test {
namespace {

    class NetworkUniverseTest : public ::testing::Test {
    public:
        ~NetworkUniverseTest() override;

    protected:
        NetworkUniverse universe;
        FakeUdpSocket s1{universe};
        FakeUdpSocket s2{universe};
    };

    NetworkUniverseTest::~NetworkUniverseTest() = default;

    TEST_F(NetworkUniverseTest, LatencySimulation)
    {
        universe.set_latency(100);

        IP_Port s2_addr;
        ip_init(&s2_addr.ip, false);
        s2_addr.ip.ip.v4.uint32 = net_htonl(0x7F000001);
        s2_addr.port = net_htons(9004);
        s2.bind(&s2_addr);

        uint8_t data[] = "Ping";
        s1.sendto(data, 4, &s2_addr);

        // Time 0: packet sent but delivery time is 100
        universe.process_events(0);
        IP_Port from;
        uint8_t buf[10];
        ASSERT_EQ(s2.recvfrom(buf, 10, &from), -1);

        // Time 50: still not delivered
        universe.process_events(50);
        ASSERT_EQ(s2.recvfrom(buf, 10, &from), -1);

        // Time 100: delivered
        universe.process_events(100);
        ASSERT_EQ(s2.recvfrom(buf, 10, &from), 4);
    }

    TEST_F(NetworkUniverseTest, RoutesBasedOnIpAndPort)
    {
        IP ip1{}, ip2{};
        ip_init(&ip1, false);
        ip1.ip.v4.uint32 = net_htonl(0x01010101);
        ip_init(&ip2, false);
        ip2.ip.v4.uint32 = net_htonl(0x02020202);

        uint16_t port = 33445;

        FakeUdpSocket sock1{universe};
        FakeUdpSocket sock2{universe};

        sock1.set_ip(ip1);
        sock2.set_ip(ip2);

        IP_Port addr1{ip1, net_htons(port)};
        IP_Port addr2{ip2, net_htons(port)};

        ASSERT_EQ(sock1.bind(&addr1), 0);
        ASSERT_EQ(sock2.bind(&addr2), 0);

        const char *msg1 = "To IP 1";
        const char *msg2 = "To IP 2";

        FakeUdpSocket sender{universe};
        sender.sendto(reinterpret_cast<const uint8_t *>(msg1), strlen(msg1), &addr1);
        sender.sendto(reinterpret_cast<const uint8_t *>(msg2), strlen(msg2), &addr2);

        universe.process_events(0);

        uint8_t buf[100];
        IP_Port from;

        int len1 = sock1.recvfrom(buf, sizeof(buf), &from);
        ASSERT_GT(len1, 0);
        EXPECT_EQ(std::string(reinterpret_cast<char *>(buf), static_cast<std::size_t>(len1)), msg1);

        int len2 = sock2.recvfrom(buf, sizeof(buf), &from);
        ASSERT_GT(len2, 0);
        EXPECT_EQ(std::string(reinterpret_cast<char *>(buf), static_cast<std::size_t>(len2)), msg2);
    }

    TEST_F(NetworkUniverseTest, FindFreePortIsIpSpecific)
    {
        IP ip1{}, ip2{};
        ip_init(&ip1, false);
        ip1.ip.v4.uint32 = net_htonl(0x01010101);
        ip_init(&ip2, false);
        ip2.ip.v4.uint32 = net_htonl(0x02020202);

        FakeUdpSocket sock1{universe};
        sock1.set_ip(ip1);

        uint16_t port = 33445;
        IP_Port addr1{ip1, net_htons(port)};
        ASSERT_EQ(sock1.bind(&addr1), 0);

        // Port 33445 should be busy for ip1, but free for ip2
        EXPECT_EQ(universe.find_free_port(ip1, port), port + 1);
        EXPECT_EQ(universe.find_free_port(ip2, port), port);
    }

    TEST_F(NetworkUniverseTest, IpPortKeyEqualityRobustness)
    {
        IP ip1{}, ip2{};
        ip_init(&ip1, false);
        ip1.ip.v4.uint32 = net_htonl(0x7F000001);
        ip_init(&ip2, false);
        ip2.ip.v4.uint32 = net_htonl(0x7F000001);

        uint16_t port = 12345;

        // Force different garbage in the union padding for IPv4
        // The union is 16 bytes. IP4 is 4 bytes. Trailing 12 bytes are unused.
        memset(ip1.ip.v6.uint8 + 4, 0x11, 12);
        memset(ip2.ip.v6.uint8 + 4, 0x22, 12);

        NetworkUniverse::IP_Port_Key key1{ip1, port};
        NetworkUniverse::IP_Port_Key key2{ip2, port};

        // They should be considered equal (neither is less than the other)
        EXPECT_FALSE(key1 < key2);
        EXPECT_FALSE(key2 < key1);

        // Now try with different IPv4 but same garbage
        ip2.ip.v4.uint32 = net_htonl(0x7F000002);
        memset(ip2.ip.v6.uint8 + 4, 0x11, 12);  // same garbage as ip1
        NetworkUniverse::IP_Port_Key key3{ip2, port};

        EXPECT_TRUE(key1 < key3 || key3 < key1);
    }

    TEST_F(NetworkUniverseTest, IPv4v6Distinction)
    {
        IP ip1{}, ip2{};
        ip_init(&ip1, false);  // IPv4
        ip1.ip.v4.uint32 = net_htonl(0x01020304);
        ip_init(&ip2, true);  // IPv6
        // Set IPv6 bytes to match IPv4 bytes at the beginning
        memset(ip2.ip.v6.uint8, 0, 16);
        ip2.ip.v6.uint32[0] = net_htonl(0x01020304);

        uint16_t port = 12345;

        NetworkUniverse::IP_Port_Key key1{ip1, port};
        NetworkUniverse::IP_Port_Key key2{ip2, port};

        // Different families must be different even if underlying bytes happen to match
        EXPECT_TRUE(key1 < key2 || key2 < key1);
    }

    TEST_F(NetworkUniverseTest, ManyNodes)
    {
        const int num_nodes = 5000;
        struct NodeInfo {
            std::unique_ptr<FakeUdpSocket> sock;
            IP_Port addr;
        };
        std::vector<NodeInfo> nodes;
        nodes.reserve(num_nodes);

        for (int i = 0; i < num_nodes; ++i) {
            auto sock = std::make_unique<FakeUdpSocket>(universe);
            IP ip{};
            ip_init(&ip, false);
            ip.ip.v4.uint32 = net_htonl(0x0A000000 + i);  // 10.0.x.y
            sock->set_ip(ip);

            IP_Port addr{ip, net_htons(33445)};
            ASSERT_EQ(sock->bind(&addr), 0);
            nodes.push_back({std::move(sock), addr});
        }

        const int num_messages = 100;
        // Send messages from first num_messages to last num_messages nodes
        for (int i = 0; i < num_messages; ++i) {
            const char *msg = "Stress test";
            nodes[i].sock->sendto(reinterpret_cast<const uint8_t *>(msg), strlen(msg),
                &nodes[num_nodes - 1 - i].addr);
        }

        universe.process_events(0);

        for (int i = 0; i < num_messages; ++i) {
            uint8_t buf[100];
            IP_Port from;
            int len = nodes[num_nodes - 1 - i].sock->recvfrom(buf, sizeof(buf), &from);
            ASSERT_GT(len, 0);
            EXPECT_EQ(std::string(reinterpret_cast<char *>(buf), static_cast<std::size_t>(len)),
                "Stress test");
            EXPECT_TRUE(ip_equal(&from.ip, &nodes[i].addr.ip));
        }
    }

    TEST_F(NetworkUniverseTest, IpPadding)
    {
        IP ip1{};
        ip_init(&ip1, false);
        ip1.ip.v4.uint32 = net_htonl(0x7F000001);

        FakeUdpSocket sock{universe};
        sock.set_ip(ip1);
        IP_Port bind_addr{ip1, net_htons(12345)};
        ASSERT_EQ(sock.bind(&bind_addr), 0);

        // Create an address with garbage in the padding
        IP_Port target_addr;
        memset(&target_addr, 0xAA, sizeof(target_addr));
        ip_init(&target_addr.ip, false);
        target_addr.ip.ip.v4.uint32 = net_htonl(0x7F000001);
        target_addr.port = net_htons(12345);

        FakeUdpSocket sender{universe};
        const char *msg = "Padding test";
        sender.sendto(reinterpret_cast<const uint8_t *>(msg), strlen(msg), &target_addr);

        universe.process_events(0);

        uint8_t buf[100];
        IP_Port from;
        int len = sock.recvfrom(buf, sizeof(buf), &from);

        // If this fails, it means NetworkUniverse is not robust against padding garbage
        ASSERT_GT(len, 0);
        EXPECT_EQ(std::string(reinterpret_cast<char *>(buf), static_cast<std::size_t>(len)),
            "Padding test");
    }

    TEST_F(NetworkUniverseTest, TcpRoutingSpecificity)
    {
        IP ip1{};
        ip_init(&ip1, false);
        ip1.ip.v4.uint32 = net_htonl(0x0A000001);  // 10.0.0.1

        uint16_t port = 12345;
        IP_Port local_addr{ip1, net_htons(port)};

        FakeTcpSocket listen_sock(universe);
        listen_sock.set_ip(ip1);
        listen_sock.bind(&local_addr);
        listen_sock.listen(5);

        IP remote_ip{};
        ip_init(&remote_ip, false);
        remote_ip.ip.v4.uint32 = net_htonl(0x0A000002);  // 10.0.0.2
        IP_Port remote_addr{remote_ip, net_htons(33445)};

        auto established_sock = FakeTcpSocket::create_connected(universe, remote_addr, port);
        established_sock->set_ip(ip1);
        universe.bind_tcp(ip1, port, established_sock.get());

        // Send a data packet from remote to local
        Packet p{};
        p.from = remote_addr;
        p.to = local_addr;
        p.is_tcp = true;
        p.tcp_flags = 0x10;  // ACK (Data)
        const char *data = "Specific";
        p.data.assign(data, data + strlen(data));

        universe.send_packet(p);
        universe.process_events(0);

        // established_sock should have received it
        EXPECT_EQ(established_sock->recv_buffer_size(), strlen(data));

        // listen_sock should NOT have received it (it doesn't have a buffer, but it shouldn't have
        // been called) We can't easily check listen_sock wasn't called without mocks or checking
        // logs, but we can check that it didn't create a new pending connection.
        EXPECT_FALSE(listen_sock.is_readable());
    }

    TEST_F(NetworkUniverseTest, PacketOrdering)
    {
        IP ip1{}, ip2{};
        ip_init(&ip1, false);
        ip1.ip.v4.uint32 = net_htonl(0x0A000001);
        ip_init(&ip2, false);
        ip2.ip.v4.uint32 = net_htonl(0x0A000002);

        uint16_t port = 33445;
        IP_Port addr1{ip1, net_htons(port)};
        IP_Port addr2{ip2, net_htons(port)};

        FakeUdpSocket sock1{universe};
        sock1.set_ip(ip1);
        sock1.bind(&addr1);

        FakeUdpSocket sock2{universe};
        sock2.set_ip(ip2);
        sock2.bind(&addr2);

        // Send 10 packets with the same delivery time (global latency = 0)
        for (int i = 0; i < 10; ++i) {
            uint8_t data = static_cast<uint8_t>(i);
            sock1.sendto(&data, 1, &addr2);
        }

        universe.process_events(0);

        // They should be received in the exact order they were sent
        for (int i = 0; i < 10; ++i) {
            uint8_t buf[1];
            IP_Port from;
            ASSERT_EQ(sock2.recvfrom(buf, 1, &from), 1);
            EXPECT_EQ(buf[0], i) << "Packet " << i << " was delivered out of order";
        }
    }

}  // namespace
}  // namespace tox::test
