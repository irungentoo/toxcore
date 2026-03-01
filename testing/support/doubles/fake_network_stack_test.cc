#include "fake_network_stack.hh"

#include <gtest/gtest.h>

#include "network_universe.hh"

#ifdef _WIN32
#define WIN32_LEAN_AND_MEAN
#define NOMINMAX
#include <winsock2.h>
#else
#include <netinet/in.h>
#include <sys/socket.h>
#endif

namespace tox::test {
namespace {

    class FakeNetworkStackTest : public ::testing::Test {
    public:
        FakeNetworkStackTest()
            : stack{universe, make_ip(0x7F000001)}
        {
        }
        ~FakeNetworkStackTest() override;

    protected:
        NetworkUniverse universe;
        FakeNetworkStack stack;
    };

    FakeNetworkStackTest::~FakeNetworkStackTest() = default;

    TEST_F(FakeNetworkStackTest, SocketCreationAndLifecycle)
    {
        Socket udp_sock = stack.socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
        ASSERT_NE(net_socket_to_native(udp_sock), -1);

        // Check introspection
        ASSERT_NE(stack.get_udp_socket(udp_sock), nullptr);

        // Bind
        IP_Port addr;
        ip_init(&addr.ip, false);
        addr.ip.ip.v4.uint32 = 0;
        addr.port = net_htons(9002);
        ASSERT_EQ(stack.bind(udp_sock, &addr), 0);

        // Check introspection again
        auto sockets = stack.get_bound_udp_sockets();
        ASSERT_EQ(sockets.size(), 1);
        EXPECT_EQ(sockets[0]->local_port(), 9002);

        ASSERT_EQ(stack.close(udp_sock), 0);
        ASSERT_EQ(stack.get_bound_udp_sockets().size(), 0);
    }

    TEST_F(FakeNetworkStackTest, TcpSocketThroughStack)
    {
        Socket tcp_sock = stack.socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
        ASSERT_NE(net_socket_to_native(tcp_sock), -1);

        IP_Port addr;
        ip_init(&addr.ip, false);
        addr.ip.ip.v4.uint32 = 0;
        addr.port = net_htons(9003);
        ASSERT_EQ(stack.bind(tcp_sock, &addr), 0);
        ASSERT_EQ(stack.listen(tcp_sock, 5), 0);

        // Connect from another stack
        FakeNetworkStack client_stack{universe, make_ip(0x7F000002)};
        Socket client_sock = client_stack.socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);

        IP_Port server_addr;
        ip_init(&server_addr.ip, false);
        server_addr.ip.ip.v4.uint32 = net_htonl(0x7F000001);  // Localhost
        server_addr.port = net_htons(9003);

        ASSERT_EQ(client_stack.connect(client_sock, &server_addr), -1);
        ASSERT_EQ(errno, EINPROGRESS);

        universe.process_events(0);  // SYN
        universe.process_events(0);  // SYN-ACK
        universe.process_events(0);  // ACK

        Socket accepted = stack.accept(tcp_sock);
        ASSERT_NE(net_socket_to_native(accepted), -1);
    }

    TEST_F(FakeNetworkStackTest, LoopbackRedirection)
    {
        // 1. Create a stack with a specific IP (20.0.0.1)
        FakeNetworkStack my_stack{universe, make_ip(0x14000001)};
        Socket sock = my_stack.socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);

        IP_Port bind_addr;
        ip_init(&bind_addr.ip, false);
        bind_addr.ip.ip.v4.uint32 = net_htonl(0x14000001);
        bind_addr.port = net_htons(12345);
        ASSERT_EQ(my_stack.bind(sock, &bind_addr), 0);
        ASSERT_EQ(my_stack.listen(sock, 5), 0);

        // 2. Connect to 127.0.0.1:12345 from the same stack
        Socket client = my_stack.socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);

        IP_Port connect_addr;
        ip_init(&connect_addr.ip, false);
        connect_addr.ip.ip.v4.uint32 = net_htonl(0x7F000001);
        connect_addr.port = net_htons(12345);

        // Should redirect to 20.0.0.1:12345 because 127.0.0.1 is not bound
        ASSERT_EQ(my_stack.connect(client, &connect_addr), -1);
        ASSERT_EQ(errno, EINPROGRESS);

        universe.process_events(0);  // SYN

        Socket accepted = my_stack.accept(sock);
        ASSERT_NE(net_socket_to_native(accepted), -1);
    }

    TEST_F(FakeNetworkStackTest, ImplicitBindAvoidsCollision)
    {
        // Bind server to 33445 (default start of find_free_port)
        Socket server = stack.socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
        IP_Port addr;
        ip_init(&addr.ip, false);
        addr.ip.ip.v4.uint32 = 0;
        addr.port = net_htons(33445);
        ASSERT_EQ(stack.bind(server, &addr), 0);

        // Create client and connect (implicit bind)
        Socket client = stack.socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
        IP_Port server_addr;
        ip_init(&server_addr.ip, false);
        server_addr.ip.ip.v4.uint32 = net_htonl(0x7F000001);
        server_addr.port = net_htons(33445);

        // Should find a free port (not 33445)
        ASSERT_EQ(stack.connect(client, &server_addr), -1);
        ASSERT_EQ(errno, EINPROGRESS);

        auto *client_obj = stack.get_sock(client);
        ASSERT_NE(client_obj, nullptr);
        ASSERT_NE(client_obj->local_port(), 33445);
    }

}  // namespace
}  // namespace tox::test
