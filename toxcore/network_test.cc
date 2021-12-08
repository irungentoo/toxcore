#include "network.h"

#include <gtest/gtest.h>

namespace {

TEST(IpNtoa, DoesntWriteOutOfBounds) {
  char ip_str[IP_NTOA_LEN];
  IP ip;
  ip.family = net_family_ipv6;
  ip.ip.v6.uint64[0] = -1;
  ip.ip.v6.uint64[1] = -1;

  ip_ntoa(&ip, ip_str, sizeof(ip_str));

  EXPECT_EQ(std::string(ip_str), "[ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff]");
  EXPECT_LT(std::string(ip_str).length(), IP_NTOA_LEN);
}

}  // namespace
