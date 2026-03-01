#include <gtest/gtest.h>

#include "fake_sockets.hh"
#include "network_universe.hh"

namespace tox::test {
namespace {

    class FakeNetworkTcpTest : public ::testing::Test {
    protected:
        NetworkUniverse universe;

        IP make_ip(uint8_t a, uint8_t b, uint8_t c, uint8_t d)
        {
            IP ip;
            ip_init(&ip, false);
            ip.ip.v4.uint8[0] = a;
            ip.ip.v4.uint8[1] = b;
            ip.ip.v4.uint8[2] = c;
            ip.ip.v4.uint8[3] = d;
            return ip;
        }
    };

    TEST_F(FakeNetworkTcpTest, MultipleConnectionsToSamePort)
    {
        universe.set_verbose(true);
        IP server_ip = make_ip(10, 0, 0, 1);
        uint16_t server_port = 12345;

        FakeTcpSocket server(universe);
        server.set_ip(server_ip);
        IP_Port server_addr{server_ip, net_htons(server_port)};
        ASSERT_EQ(server.bind(&server_addr), 0);
        ASSERT_EQ(server.listen(5), 0);

        // Client 1
        IP client1_ip = make_ip(10, 0, 0, 2);
        FakeTcpSocket client1(universe);
        client1.set_ip(client1_ip);
        client1.connect(&server_addr);

        // Client 2 (same IP as client 1, different port)
        FakeTcpSocket client2(universe);
        client2.set_ip(client1_ip);
        client2.connect(&server_addr);

        // Handshake for both
        // 1. SYNs
        universe.process_events(0);
        universe.process_events(0);

        // 2. SYN-ACKs
        universe.process_events(0);
        universe.process_events(0);

        // 3. ACKs
        universe.process_events(0);
        universe.process_events(0);

        auto accepted1 = server.accept(nullptr);
        auto accepted2 = server.accept(nullptr);

        ASSERT_NE(accepted1, nullptr);
        ASSERT_NE(accepted2, nullptr);

        EXPECT_EQ(
            static_cast<FakeTcpSocket *>(accepted1.get())->state(), FakeTcpSocket::ESTABLISHED);
        EXPECT_EQ(
            static_cast<FakeTcpSocket *>(accepted2.get())->state(), FakeTcpSocket::ESTABLISHED);

        // Verify data isolation
        const char *msg1 = "Message 1";
        const char *msg2 = "Message 2";

        client1.send(reinterpret_cast<const uint8_t *>(msg1), strlen(msg1));
        client2.send(reinterpret_cast<const uint8_t *>(msg2), strlen(msg2));

        universe.process_events(0);
        universe.process_events(0);

        uint8_t buf[100];
        int len1 = accepted1->recv(buf, sizeof(buf));
        EXPECT_EQ(len1, strlen(msg1));
        int len2 = accepted2->recv(buf, sizeof(buf));
        EXPECT_EQ(len2, strlen(msg2));
    }

    TEST_F(FakeNetworkTcpTest, DuplicateSynCreatesDuplicateConnections)
    {
        universe.set_verbose(true);
        IP server_ip = make_ip(10, 0, 0, 1);
        uint16_t server_port = 12345;

        FakeTcpSocket server(universe);
        server.set_ip(server_ip);
        IP_Port server_addr{server_ip, net_htons(server_port)};
        server.bind(&server_addr);
        server.listen(5);

        IP client_ip = make_ip(10, 0, 0, 2);
        IP_Port client_addr{client_ip, net_htons(33445)};

        Packet p{};
        p.from = client_addr;
        p.to = server_addr;
        p.is_tcp = true;
        p.tcp_flags = 0x02;  // SYN
        p.seq = 100;

        universe.send_packet(p);
        universe.send_packet(p);  // Duplicate SYN

        universe.process_events(0);
        universe.process_events(0);

        // Now send ACK from client
        Packet ack{};
        ack.from = client_addr;
        ack.to = server_addr;
        ack.is_tcp = true;
        ack.tcp_flags = 0x10;  // ACK
        ack.ack = 101;

        universe.send_packet(ack);
        universe.process_events(0);

        auto accepted1 = server.accept(nullptr);
        auto accepted2 = server.accept(nullptr);

        ASSERT_NE(accepted1, nullptr);
        EXPECT_EQ(accepted2, nullptr);  // This should pass now
    }

    TEST_F(FakeNetworkTcpTest, PeerCloseClearsConnection)
    {
        universe.set_verbose(true);
        IP server_ip = make_ip(10, 0, 0, 1);
        uint16_t server_port = 12345;

        FakeTcpSocket server(universe);
        server.set_ip(server_ip);
        IP_Port server_addr{server_ip, net_htons(server_port)};
        server.bind(&server_addr);
        server.listen(5);

        IP client_ip = make_ip(10, 0, 0, 2);
        FakeTcpSocket client(universe);
        client.set_ip(client_ip);
        client.connect(&server_addr);

        // Handshake
        universe.process_events(0);  // SYN
        universe.process_events(0);  // SYN-ACK
        universe.process_events(0);  // ACK

        auto accepted = server.accept(nullptr);
        ASSERT_NE(accepted, nullptr);
        EXPECT_EQ(
            static_cast<FakeTcpSocket *>(accepted.get())->state(), FakeTcpSocket::ESTABLISHED);

        // Client closes
        client.close();
        universe.process_events(0);  // Deliver RST/FIN

        // Server should no longer be ESTABLISHED
        EXPECT_EQ(static_cast<FakeTcpSocket *>(accepted.get())->state(), FakeTcpSocket::CLOSED);

        // Now if client reconnects with same port
        FakeTcpSocket client2(universe);
        client2.set_ip(client_ip);
        client2.connect(&server_addr);
        universe.process_events(0);  // Deliver SYN

        // Node 2 port 20002 should have: 1 LISTEN, 0 ESTABLISHED (old one gone), 1 SYN_RECEIVED
        // (new one) Total targets should be 2.
    }

    TEST_F(FakeNetworkTcpTest, DataNotProcessedByMultipleSockets)
    {
        universe.set_verbose(true);
        IP server_ip = make_ip(10, 0, 0, 1);
        uint16_t server_port = 12345;

        FakeTcpSocket server(universe);
        server.set_ip(server_ip);
        IP_Port server_addr{server_ip, net_htons(server_port)};
        server.bind(&server_addr);
        server.listen(5);

        IP client_ip = make_ip(10, 0, 0, 2);
        IP_Port client_addr{client_ip, net_htons(33445)};

        // Manually create two "established" sockets on the same port for the same peer
        // This simulates a bug where duplicate connections were allowed.
        auto sock1 = FakeTcpSocket::create_connected(universe, client_addr, server_port);
        sock1->set_ip(server_ip);
        auto sock2 = FakeTcpSocket::create_connected(universe, client_addr, server_port);
        sock2->set_ip(server_ip);

        universe.bind_tcp(server_ip, server_port, sock1.get());
        universe.bind_tcp(server_ip, server_port, sock2.get());

        // Send data from client to server
        Packet p{};
        p.from = client_addr;
        p.to = server_addr;
        p.is_tcp = true;
        p.tcp_flags = 0x10;  // ACK (Data)
        const char *data = "Unique";
        p.data.assign(data, data + strlen(data));

        universe.send_packet(p);
        universe.process_events(0);

        // Only ONE of them should have received it, or at least they shouldn't BOTH have it
        // in a way that suggests duplicate delivery.
        EXPECT_TRUE((sock1->recv_buffer_size() == strlen(data))
            ^ (sock2->recv_buffer_size() == strlen(data)));
    }

    TEST_F(FakeNetworkTcpTest, ConnectionCollision)
    {
        universe.set_verbose(true);
        IP server_ip = make_ip(10, 0, 0, 1);
        uint16_t server_port = 12345;

        FakeTcpSocket server(universe);
        server.set_ip(server_ip);
        IP_Port server_addr{server_ip, net_htons(server_port)};
        server.bind(&server_addr);
        server.listen(5);

        IP client_ip = make_ip(10, 0, 0, 2);

        FakeTcpSocket client1(universe);
        client1.set_ip(client_ip);
        // Bind to specific port to force collision later
        IP_Port client_bind_addr{client_ip, net_htons(33445)};
        client1.bind(&client_bind_addr);
        client1.connect(&server_addr);

        // Handshake 1
        universe.process_events(0);  // SYN
        universe.process_events(0);  // SYN-ACK
        universe.process_events(0);  // ACK

        auto accepted1 = server.accept(nullptr);
        ASSERT_NE(accepted1, nullptr);
        EXPECT_EQ(
            static_cast<FakeTcpSocket *>(accepted1.get())->state(), FakeTcpSocket::ESTABLISHED);

        // Now client 1 "reconnects" (e.g. after a crash or timeout, but using same port)
        FakeTcpSocket client2(universe);
        client2.set_ip(client_ip);
        client2.bind(&client_bind_addr);  // Forced collision
        client2.connect(&server_addr);

        // Deliver new SYN
        universe.process_events(0);

        // server_addr port 12345 now has:
        // 1. LISTEN socket
        // 2. accepted1 (ESTABLISHED with 10.0.0.2:33445)

        // In our simplified simulation, the ESTABLISHED socket now handles the SYN by returning
        // true (ignoring it). So no new connection is created.
        auto accepted2 = server.accept(nullptr);
        EXPECT_EQ(accepted2, nullptr);

        const char *msg1 = "Data 1";
        client1.send(reinterpret_cast<const uint8_t *>(msg1), strlen(msg1));
        universe.process_events(0);

        // Data should still go to accepted1
        EXPECT_EQ(accepted1->recv_buffer_size(), strlen(msg1));
    }

    TEST_F(FakeNetworkTcpTest, LoopbackConnection)
    {
        universe.set_verbose(true);
        IP node_ip = make_ip(10, 0, 0, 1);
        uint16_t port = 12345;

        FakeTcpSocket server(universe);
        server.set_ip(node_ip);
        IP_Port listen_addr{node_ip, net_htons(port)};
        server.bind(&listen_addr);
        server.listen(5);

        FakeTcpSocket client(universe);
        client.set_ip(node_ip);
        IP loopback_ip;
        ip_init(&loopback_ip, false);
        loopback_ip.ip.v4.uint32 = net_htonl(0x7F000001);
        IP_Port server_loopback_addr{loopback_ip, net_htons(port)};

        client.connect(&server_loopback_addr);

        // SYN (Client -> 127.0.0.1:12345)
        universe.process_events(0);

        // SYN-ACK (Server -> Client)
        universe.process_events(0);

        // ACK (Client -> Server)
        universe.process_events(0);

        EXPECT_EQ(client.state(), FakeTcpSocket::ESTABLISHED);
        auto accepted = server.accept(nullptr);
        ASSERT_NE(accepted, nullptr);
        EXPECT_EQ(
            static_cast<FakeTcpSocket *>(accepted.get())->state(), FakeTcpSocket::ESTABLISHED);

        // Data Transfer
        const char *msg = "Loopback";
        client.send(reinterpret_cast<const uint8_t *>(msg), strlen(msg));
        universe.process_events(0);

        uint8_t buf[100];
        int len = accepted->recv(buf, sizeof(buf));
        ASSERT_EQ(len, strlen(msg));
        EXPECT_EQ(std::string(reinterpret_cast<char *>(buf), len), msg);
    }

    TEST_F(FakeNetworkTcpTest, SimultaneousConnect)
    {
        universe.set_verbose(true);
        IP ipA = make_ip(10, 0, 0, 1);
        IP ipB = make_ip(10, 0, 0, 2);
        uint16_t portA = 10001;
        uint16_t portB = 10002;

        FakeTcpSocket sockA(universe);
        sockA.set_ip(ipA);
        IP_Port addrA{ipA, net_htons(portA)};
        sockA.bind(&addrA);
        sockA.listen(5);

        FakeTcpSocket sockB(universe);
        sockB.set_ip(ipB);
        IP_Port addrB{ipB, net_htons(portB)};
        sockB.bind(&addrB);
        sockB.listen(5);

        // A connects to B
        sockA.connect(&addrB);
        // B connects to A
        sockB.connect(&addrA);

        // This is "simultaneous open" in TCP but here they are also LISTENing.
        // Toxcore uses this pattern sometimes.

        universe.process_events(0);  // SYN from A to B
        universe.process_events(0);  // SYN from B to A

        universe.process_events(0);  // SYN-ACK from B to A (for A's SYN)
        universe.process_events(0);  // SYN-ACK from A to B (for B's SYN)

        universe.process_events(0);  // ACK from A to B
        universe.process_events(0);  // ACK from B to A

        EXPECT_EQ(sockA.state(), FakeTcpSocket::ESTABLISHED);
        EXPECT_EQ(sockB.state(), FakeTcpSocket::ESTABLISHED);
    }

    TEST_F(FakeNetworkTcpTest, DataInHandshakeAck)
    {
        universe.set_verbose(true);
        IP server_ip = make_ip(10, 0, 0, 1);
        uint16_t server_port = 12345;

        FakeTcpSocket server(universe);
        server.set_ip(server_ip);
        IP_Port server_addr{server_ip, net_htons(server_port)};
        server.bind(&server_addr);
        server.listen(5);

        IP client_ip = make_ip(10, 0, 0, 2);
        IP_Port client_addr{client_ip, net_htons(33445)};

        // 1. SYN
        Packet syn{};
        syn.from = client_addr;
        syn.to = server_addr;
        syn.is_tcp = true;
        syn.tcp_flags = 0x02;
        universe.send_packet(syn);
        universe.process_events(0);

        // 2. SYN-ACK (Server -> Client)
        universe.process_events(0);

        // 3. ACK + Data (Client -> Server)
        Packet ack{};
        ack.from = client_addr;
        ack.to = server_addr;
        ack.is_tcp = true;
        ack.tcp_flags = 0x10;
        const char *data = "HandshakeData";
        ack.data.assign(data, data + strlen(data));
        universe.send_packet(ack);
        universe.process_events(0);

        auto accepted = server.accept(nullptr);
        ASSERT_NE(accepted, nullptr);
        EXPECT_EQ(accepted->recv_buffer_size(), strlen(data));
    }

    TEST_F(FakeNetworkTcpTest, DataInSynAck)
    {
        universe.set_verbose(true);
        IP ipA = make_ip(10, 0, 0, 1);
        IP ipB = make_ip(10, 0, 0, 2);
        uint16_t portA = 10001;
        uint16_t portB = 10002;

        FakeTcpSocket sockA(universe);
        sockA.set_ip(ipA);
        IP_Port addrA{ipA, net_htons(portA)};
        sockA.bind(&addrA);
        sockA.listen(5);

        FakeTcpSocket sockB(universe);
        sockB.set_ip(ipB);
        IP_Port addrB{ipB, net_htons(portB)};
        sockB.bind(&addrB);
        sockB.listen(5);

        // A connects to B
        sockA.connect(&addrB);
        // B connects to A
        sockB.connect(&addrA);

        universe.process_events(0);  // SYN from A to B
        universe.process_events(0);  // SYN from B to A

        // Now A receives B's SYN and transitions to SYN_RECEIVED, sending SYN-ACK.
        // We want to simulate B sending SYN-ACK WITH DATA to A.
        Packet syn_ack_data{};
        syn_ack_data.from = addrB;
        syn_ack_data.to = addrA;
        syn_ack_data.is_tcp = true;
        syn_ack_data.tcp_flags = 0x12;  // SYN | ACK
        const char *msg = "SynAckData";
        syn_ack_data.data.assign(msg, msg + strlen(msg));

        universe.send_packet(syn_ack_data);
        universe.process_events(0);  // A receives SYN-ACK with data

        EXPECT_EQ(sockA.state(), FakeTcpSocket::ESTABLISHED);
        EXPECT_EQ(sockA.recv_buffer_size(), strlen(msg));
    }

    TEST_F(FakeNetworkTcpTest, LoopbackWithNodeIPMixed)
    {
        universe.set_verbose(true);
        IP node_ip = make_ip(10, 0, 0, 1);
        uint16_t port = 12345;

        FakeTcpSocket server(universe);
        server.set_ip(node_ip);
        IP_Port listen_addr{node_ip, net_htons(port)};
        server.bind(&listen_addr);
        server.listen(5);

        FakeTcpSocket client(universe);
        client.set_ip(node_ip);
        IP loopback_ip;
        ip_init(&loopback_ip, false);
        loopback_ip.ip.v4.uint32 = net_htonl(0x7F000001);
        IP_Port server_loopback_addr{loopback_ip, net_htons(port)};

        // Client connects to 127.0.0.1
        client.connect(&server_loopback_addr);

        universe.process_events(0);  // SYN (Client -> 127.0.0.1)
        universe.process_events(0);  // SYN-ACK (Server -> Client)
        universe.process_events(0);  // ACK (Client -> Server)

        EXPECT_EQ(client.state(), FakeTcpSocket::ESTABLISHED);
        auto accepted = server.accept(nullptr);
        ASSERT_NE(accepted, nullptr);

        // Now manually simulate a packet coming from the server's EXTERNAL IP to the client.
        // This happens because the server socket is bound to node_ip, so its packets might
        // be delivered as coming from node_ip even if the client connected to 127.0.0.1.
        Packet p{};
        p.from = listen_addr;  // node_ip:port
        p.to.ip = node_ip;
        p.to.port = net_htons(client.local_port());
        p.is_tcp = true;
        p.tcp_flags = 0x10;  // ACK
        const char *msg = "MixedIP";
        p.data.assign(msg, msg + strlen(msg));

        universe.send_packet(p);
        universe.process_events(0);

        EXPECT_EQ(client.recv_buffer_size(), strlen(msg));
    }

}
}
