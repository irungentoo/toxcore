#include "network.h"

#include <gtest/gtest.h>

namespace {

TEST(IpNtoa, DoesntWriteOutOfBounds)
{
    char ip_str[IP_NTOA_LEN];
    IP ip;
    ip.family = net_family_ipv6;
    ip.ip.v6.uint64[0] = -1;
    ip.ip.v6.uint64[1] = -1;

    ip_ntoa(&ip, ip_str, sizeof(ip_str));

    EXPECT_EQ(std::string(ip_str), "ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff");
    EXPECT_LT(std::string(ip_str).length(), IP_NTOA_LEN);
}

TEST(IpNtoa, DoesntOverrunSmallBuffer)
{
    // We have to try really hard to trick the compiler here not to realise that
    // 10 is too small a buffer for the snprintf inside ip_ntoa and error out.
    std::istringstream ss("10");
    size_t len;
    ss >> len;
    std::vector<char> ip_str(len);
    IP *ip = nullptr;

    ip_ntoa(ip, ip_str.data(), ip_str.size());

    EXPECT_EQ(std::string(ip_str.data()), "Bad buf l");
}

TEST(IpNtoa, ReportsInvalidIpFamily)
{
    char ip_str[IP_NTOA_LEN];
    IP ip;
    ip.family.value = 255 - net_family_ipv6.value;
    ip.ip.v4.uint32 = 0;

    ip_ntoa(&ip, ip_str, sizeof(ip_str));

    EXPECT_EQ(std::string(ip_str), "(IP invalid, family 245)");
}

TEST(IpNtoa, FormatsIPv4)
{
    char ip_str[IP_NTOA_LEN];
    IP ip;
    ip.family = net_family_ipv4;
    ip.ip.v4.uint8[0] = 192;
    ip.ip.v4.uint8[1] = 168;
    ip.ip.v4.uint8[2] = 0;
    ip.ip.v4.uint8[3] = 13;

    ip_ntoa(&ip, ip_str, sizeof(ip_str));

    EXPECT_EQ(std::string(ip_str), "192.168.0.13");
}

TEST(IpParseAddr, FormatsIPv4)
{
    char ip_str[IP_NTOA_LEN];
    IP ip;
    ip.family = net_family_ipv4;
    ip.ip.v4.uint8[0] = 192;
    ip.ip.v4.uint8[1] = 168;
    ip.ip.v4.uint8[2] = 0;
    ip.ip.v4.uint8[3] = 13;

    ip_parse_addr(&ip, ip_str, sizeof(ip_str));

    EXPECT_EQ(std::string(ip_str), "192.168.0.13");
}

TEST(IpParseAddr, FormatsIPv6)
{
    char ip_str[IP_NTOA_LEN];
    IP ip;
    ip.family = net_family_ipv6;
    ip.ip.v6.uint64[0] = -1;
    ip.ip.v6.uint64[1] = -1;

    ip_parse_addr(&ip, ip_str, sizeof(ip_str));

    EXPECT_EQ(std::string(ip_str), "ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff");
}

}  // namespace
