#include "fake_sockets.hh"

#include <gtest/gtest.h>

#include "network_universe.hh"

namespace tox::test {
namespace {

    class FakeTcpSocketTest : public ::testing::Test {
    public:
        ~FakeTcpSocketTest() override;

    protected:
        NetworkUniverse universe;
        FakeTcpSocket server{universe};
        FakeTcpSocket client{universe};
    };

    FakeTcpSocketTest::~FakeTcpSocketTest() = default;

    TEST_F(FakeTcpSocketTest, ConnectAndAccept)
    {
        IP_Port server_addr;
        ip_init(&server_addr.ip, false);
        server_addr.ip.ip.v4.uint32 = net_htonl(0x7F000001);
        server_addr.port = net_htons(8080);

        ASSERT_EQ(server.bind(&server_addr), 0);
        ASSERT_EQ(server.listen(5), 0);

        // Client connects
        ASSERT_EQ(client.connect(&server_addr), -1);
        ASSERT_EQ(errno, EINPROGRESS);

        // Process events (Client SYN -> Server)
        universe.process_events(0);

        // Server accepts (SYN-ACK -> Client)
        universe.process_events(0);

        // Client receives SYN-ACK, sends ACK (ACK -> Server)
        universe.process_events(0);

        // Server receives ACK, connection established
        IP_Port client_addr;
        auto accepted = server.accept(&client_addr);
        ASSERT_NE(accepted, nullptr);
        auto *accepted_tcp = static_cast<FakeTcpSocket *>(accepted.get());
        EXPECT_EQ(accepted_tcp->state(), FakeTcpSocket::ESTABLISHED);

        EXPECT_EQ(client.state(), FakeTcpSocket::ESTABLISHED);
    }

    TEST_F(FakeTcpSocketTest, DataTransfer)
    {
        IP_Port server_addr;
        ip_init(&server_addr.ip, false);
        server_addr.ip.ip.v4.uint32 = net_htonl(0x7F000001);
        server_addr.port = net_htons(8081);

        server.bind(&server_addr);
        server.listen(5);
        client.connect(&server_addr);

        // Handshake
        universe.process_events(0);  // SYN
        universe.process_events(0);  // SYN-ACK
        universe.process_events(0);  // ACK

        auto accepted = server.accept(nullptr);
        ASSERT_NE(accepted, nullptr);

        // Send data Client -> Server
        uint8_t send_buf[] = "Hello";
        ASSERT_EQ(client.send(send_buf, 5), 5);

        universe.process_events(0);  // Data packet

        uint8_t recv_buf[10];
        ASSERT_EQ(accepted->recv(recv_buf, 10), 5);
        EXPECT_EQ(std::string(reinterpret_cast<char *>(recv_buf), 5), "Hello");
    }

    TEST_F(FakeTcpSocketTest, RecvBuffering)
    {
        IP_Port server_addr;
        ip_init(&server_addr.ip, false);
        server_addr.ip.ip.v4.uint32 = net_htonl(0x7F000001);
        server_addr.port = net_htons(8082);

        server.bind(&server_addr);
        server.listen(5);
        client.connect(&server_addr);

        universe.process_events(0);  // SYN
        universe.process_events(0);  // SYN-ACK
        universe.process_events(0);  // ACK

        auto accepted = server.accept(nullptr);
        ASSERT_NE(accepted, nullptr);

        uint8_t msg1[] = "Part1";
        uint8_t msg2[] = "Part2";
        client.send(msg1, 5);
        client.send(msg2, 5);

        universe.process_events(0);  // Deliver Part1
        universe.process_events(0);  // Deliver Part2

        EXPECT_EQ(accepted->recv_buffer_size(), 10);

        uint8_t recv_buf[20];
        // Read partial
        ASSERT_EQ(accepted->recv(recv_buf, 3), 3);
        EXPECT_EQ(std::string(reinterpret_cast<char *>(recv_buf), 3), "Par");
        EXPECT_EQ(accepted->recv_buffer_size(), 7);

        // Read rest
        ASSERT_EQ(accepted->recv(recv_buf, 7), 7);
        EXPECT_EQ(std::string(reinterpret_cast<char *>(recv_buf), 7), "t1Part2");
        EXPECT_EQ(accepted->recv_buffer_size(), 0);
    }

    class FakeUdpSocketTest : public ::testing::Test {
    public:
        ~FakeUdpSocketTest() override;

    protected:
        NetworkUniverse universe;
        FakeUdpSocket server{universe};
        FakeUdpSocket client{universe};
    };

    FakeUdpSocketTest::~FakeUdpSocketTest() = default;

    TEST_F(FakeUdpSocketTest, BindAndSendTo)
    {
        IP_Port server_addr;
        ip_init(&server_addr.ip, false);
        server_addr.ip.ip.v4.uint32 = net_htonl(0x7F000001);
        server_addr.port = net_htons(9000);

        ASSERT_EQ(server.bind(&server_addr), 0);

        const char *message = "UDP Packet";
        ASSERT_EQ(client.sendto(
                      reinterpret_cast<const uint8_t *>(message), strlen(message), &server_addr),
            strlen(message));

        universe.process_events(0);

        IP_Port sender_addr;
        uint8_t recv_buf[100];
        int len = server.recvfrom(recv_buf, sizeof(recv_buf), &sender_addr);

        ASSERT_GT(len, 0);
        EXPECT_EQ(std::string(reinterpret_cast<char *>(recv_buf), len), message);
        EXPECT_EQ(sender_addr.port, net_htons(client.local_port()));
    }

    TEST_F(FakeUdpSocketTest, RecvBuffering)
    {
        IP_Port server_addr;
        ip_init(&server_addr.ip, false);
        server_addr.ip.ip.v4.uint32 = net_htonl(0x7F000001);
        server_addr.port = net_htons(9001);

        server.bind(&server_addr);

        const char *msg1 = "Msg1";
        const char *msg2 = "Msg2";

        client.sendto(reinterpret_cast<const uint8_t *>(msg1), strlen(msg1), &server_addr);
        client.sendto(reinterpret_cast<const uint8_t *>(msg2), strlen(msg2), &server_addr);

        universe.process_events(0);  // Deliver msg1
        universe.process_events(0);  // Deliver msg2

        EXPECT_EQ(server.recv_buffer_size(), 2);

        IP_Port sender;
        uint8_t buf[10];

        int len = server.recvfrom(buf, sizeof(buf), &sender);
        ASSERT_EQ(len, 4);
        EXPECT_EQ(std::string(reinterpret_cast<char *>(buf), len), "Msg1");
        EXPECT_EQ(server.recv_buffer_size(), 1);

        len = server.recvfrom(buf, sizeof(buf), &sender);
        ASSERT_EQ(len, 4);
        EXPECT_EQ(std::string(reinterpret_cast<char *>(buf), len), "Msg2");
        EXPECT_EQ(server.recv_buffer_size(), 0);
    }

    TEST_F(FakeUdpSocketTest, QueueLimit)
    {
        IP_Port server_addr;
        ip_init(&server_addr.ip, false);
        server_addr.ip.ip.v4.uint32 = net_htonl(0x7F000001);
        server_addr.port = net_htons(9002);

        ASSERT_EQ(server.bind(&server_addr), 0);

        // Fill the queue
        for (std::size_t i = 0; i < FakeUdpSocket::kMaxQueueSize; ++i) {
            uint8_t data = static_cast<uint8_t>(i % 256);
            ASSERT_EQ(client.sendto(&data, 1, &server_addr), 1);
        }

        universe.process_events(0);

        // This packet should be dropped
        uint8_t dropped_data = 0xFF;
        ASSERT_EQ(client.sendto(&dropped_data, 1, &server_addr), 1);
        universe.process_events(0);

        // Verify we can read MaxQueueSize packets
        for (std::size_t i = 0; i < FakeUdpSocket::kMaxQueueSize; ++i) {
            uint8_t recv_buf[1];
            IP_Port from;
            ASSERT_EQ(server.recvfrom(recv_buf, 1, &from), 1);
        }

        // The queue should now be empty
        uint8_t dummy[1];
        IP_Port from;
        EXPECT_EQ(server.recvfrom(dummy, 1, &from), -1);
        EXPECT_EQ(errno, EWOULDBLOCK);
    }

    TEST_F(FakeTcpSocketTest, BacklogLimit)
    {
        IP_Port server_addr;
        ip_init(&server_addr.ip, false);
        server_addr.ip.ip.v4.uint32 = net_htonl(0x7F000001);
        server_addr.port = net_htons(8082);

        ASSERT_EQ(server.bind(&server_addr), 0);
        // Small backlog for testing
        ASSERT_EQ(server.listen(2), 0);

        // Client 1
        FakeTcpSocket client1{universe};
        client1.connect(&server_addr);
        // Client 2
        FakeTcpSocket client2{universe};
        client2.connect(&server_addr);
        // Client 3 (Should be dropped)
        FakeTcpSocket client3{universe};
        client3.connect(&server_addr);

        universe.process_events(0);  // Deliver SYNs
        universe.process_events(0);  // Deliver SYN-ACKs
        universe.process_events(0);  // Deliver ACKs

        // Accept first two
        ASSERT_NE(server.accept(nullptr), nullptr);
        ASSERT_NE(server.accept(nullptr), nullptr);

        // Third should not be there
        EXPECT_EQ(server.accept(nullptr), nullptr);
        EXPECT_EQ(errno, EWOULDBLOCK);
    }

    TEST_F(FakeTcpSocketTest, BufferLimit)
    {
        IP_Port server_addr;
        ip_init(&server_addr.ip, false);
        server_addr.ip.ip.v4.uint32 = net_htonl(0x7F000001);
        server_addr.port = net_htons(8083);

        server.bind(&server_addr);
        server.listen(5);
        client.connect(&server_addr);

        // Handshake
        universe.process_events(0);  // SYN
        universe.process_events(0);  // SYN-ACK
        universe.process_events(0);  // ACK

        auto accepted = server.accept(nullptr);
        ASSERT_NE(accepted, nullptr);

        // Fill buffer to just below limit
        std::vector<uint8_t> large_data(FakeTcpSocket::kMaxBufferSize - 10, 'A');
        ASSERT_EQ(client.send(large_data.data(), large_data.size()), large_data.size());
        universe.process_events(0);

        EXPECT_EQ(accepted->recv_buffer_size(), FakeTcpSocket::kMaxBufferSize - 10);

        // Send 20 more bytes, total would exceed limit
        uint8_t extra_data[20];
        ASSERT_EQ(client.send(extra_data, 20), 20);
        universe.process_events(0);

        // Size should remain the same
        EXPECT_EQ(accepted->recv_buffer_size(), FakeTcpSocket::kMaxBufferSize - 10);
    }

}  // namespace
}  // namespace tox::test

// end of file
