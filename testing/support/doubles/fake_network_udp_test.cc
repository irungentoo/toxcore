#include <gtest/gtest.h>

#include <cstddef>

#include "fake_network_stack.hh"
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

    class FakeNetworkUdpTest : public ::testing::Test {
    public:
        FakeNetworkUdpTest()
            : ip1(make_ip(0x0A000001))  // 10.0.0.1
            , ip2(make_ip(0x0A000002))  // 10.0.0.2
            , stack1{universe, ip1}
            , stack2{universe, ip2}
        {
        }

    protected:
        NetworkUniverse universe;
        IP ip1, ip2;
        FakeNetworkStack stack1;
        FakeNetworkStack stack2;
    };

    TEST_F(FakeNetworkUdpTest, UdpExchange)
    {
        Socket sock1 = stack1.socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
        Socket sock2 = stack2.socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);

        IP_Port addr1;
        addr1.ip = ip1;
        addr1.port = net_htons(1234);
        ASSERT_EQ(stack1.bind(sock1, &addr1), 0);

        IP_Port addr2;
        addr2.ip = ip2;
        addr2.port = net_htons(5678);
        ASSERT_EQ(stack2.bind(sock2, &addr2), 0);

        const char *msg = "Hello UDP";
        std::size_t msg_len = strlen(msg) + 1;

        // Send from 1 to 2
        ASSERT_EQ(stack1.sendto(sock1, reinterpret_cast<const uint8_t *>(msg), msg_len, &addr2),
            static_cast<int>(msg_len));

        // Delivery
        universe.process_events(10);  // With some time offset

        // Receive at 2
        uint8_t buffer[1024];
        IP_Port from_addr;
        int recv_len = stack2.recvfrom(sock2, buffer, sizeof(buffer), &from_addr);

        ASSERT_EQ(recv_len, static_cast<int>(msg_len));
        EXPECT_STREQ(reinterpret_cast<const char *>(buffer), msg);
        EXPECT_EQ(net_ntohl(from_addr.ip.ip.v4.uint32), net_ntohl(ip1.ip.v4.uint32));
        EXPECT_EQ(net_ntohs(from_addr.port), 1234);

        stack1.close(sock1);
        stack2.close(sock2);
    }

}  // namespace
}  // namespace tox::test
