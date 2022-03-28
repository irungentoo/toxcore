#include "network.h"

#include <gtest/gtest.h>

namespace {

TEST(IpNtoa, DoesntWriteOutOfBounds)
{
    Ip_Ntoa ip_str;
    IP ip;
    ip.family = net_family_ipv6();
    ip.ip.v6.uint64[0] = -1;
    ip.ip.v6.uint64[1] = -1;

    net_ip_ntoa(&ip, &ip_str);

    EXPECT_EQ(std::string(ip_str.buf), "ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff");
    EXPECT_LT(std::string(ip_str.buf).length(), IP_NTOA_LEN);
}

TEST(IpNtoa, ReportsInvalidIpFamily)
{
    Ip_Ntoa ip_str;
    IP ip;
    ip.family.value = 255 - net_family_ipv6().value;
    ip.ip.v4.uint32 = 0;

    net_ip_ntoa(&ip, &ip_str);

    EXPECT_EQ(std::string(ip_str.buf), "(IP invalid, family 245)");
}

TEST(IpNtoa, FormatsIPv4)
{
    Ip_Ntoa ip_str;
    IP ip;
    ip.family = net_family_ipv4();
    ip.ip.v4.uint8[0] = 192;
    ip.ip.v4.uint8[1] = 168;
    ip.ip.v4.uint8[2] = 0;
    ip.ip.v4.uint8[3] = 13;

    net_ip_ntoa(&ip, &ip_str);

    EXPECT_EQ(std::string(ip_str.buf), "192.168.0.13");
}

TEST(IpParseAddr, FormatsIPv4)
{
    char ip_str[IP_NTOA_LEN];
    IP ip;
    ip.family = net_family_ipv4();
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
    ip.family = net_family_ipv6();
    ip.ip.v6.uint64[0] = -1;
    ip.ip.v6.uint64[1] = -1;

    ip_parse_addr(&ip, ip_str, sizeof(ip_str));

    EXPECT_EQ(std::string(ip_str), "ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff");
}

}  // namespace
