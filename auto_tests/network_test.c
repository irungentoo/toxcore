#include <stdlib.h>
#include <string.h>

#include "../testing/misc_tools.h"
#include "../toxcore/network.h"
#include "check_compat.h"

#ifndef USE_IPV6
#define USE_IPV6 1
#endif

START_TEST(test_addr_resolv_localhost)
{
#ifdef __CYGWIN__
    /* force initialization of network stack
     * normally this should happen automatically
     * cygwin doesn't do it for every network related function though
     * e.g. not for getaddrinfo... */
    net_socket(0, 0, 0);
    errno = 0;
#endif

    const char localhost[] = "localhost";

    IP ip;
    ip_init(&ip, 0); // ipv6enabled = 0

    int res = addr_resolve(localhost, &ip, nullptr);

    int error = net_error();
    const char *strerror = net_new_strerror(error);
    ck_assert_msg(res > 0, "Resolver failed: %d, %s", error, strerror);
    net_kill_strerror(strerror);

    char ip_str[IP_NTOA_LEN];
    ck_assert_msg(net_family_is_ipv4(ip.family), "Expected family TOX_AF_INET, got %u.", ip.family.value);
    const uint32_t loopback = get_ip4_loopback().uint32;
    ck_assert_msg(ip.ip.v4.uint32 == loopback, "Expected 127.0.0.1, got %s.",
                  ip_ntoa(&ip, ip_str, sizeof(ip_str)));

    ip_init(&ip, 1); // ipv6enabled = 1
    res = addr_resolve(localhost, &ip, nullptr);

#if USE_IPV6

    int localhost_split = 0;

    if (!(res & TOX_ADDR_RESOLVE_INET6)) {
        res = addr_resolve("ip6-localhost", &ip, nullptr);
        localhost_split = 1;
    }

    error = net_error();
    strerror = net_new_strerror(error);
    ck_assert_msg(res > 0, "Resolver failed: %d, %s", error, strerror);
    net_kill_strerror(strerror);

    ck_assert_msg(net_family_is_ipv6(ip.family), "Expected family TOX_AF_INET6 (%d), got %u.", TOX_AF_INET6,
                  ip.family.value);
    IP6 ip6_loopback = get_ip6_loopback();
    ck_assert_msg(!memcmp(&ip.ip.v6, &ip6_loopback, sizeof(IP6)), "Expected ::1, got %s.",
                  ip_ntoa(&ip, ip_str, sizeof(ip_str)));

    if (localhost_split) {
        printf("Localhost seems to be split in two.\n");
        return;
    }

#endif

    ip_init(&ip, 1); // ipv6enabled = 1
    ip.family = net_family_unspec;
    IP extra;
    ip_reset(&extra);
    res = addr_resolve(localhost, &ip, &extra);
    error = net_error();
    strerror = net_new_strerror(error);
    ck_assert_msg(res > 0, "Resolver failed: %d, %s", error, strerror);
    net_kill_strerror(strerror);

#if USE_IPV6
    ck_assert_msg(net_family_is_ipv6(ip.family), "Expected family TOX_AF_INET6 (%d), got %u.", TOX_AF_INET6,
                  ip.family.value);
    ck_assert_msg(!memcmp(&ip.ip.v6, &ip6_loopback, sizeof(IP6)), "Expected ::1, got %s.",
                  ip_ntoa(&ip, ip_str, sizeof(ip_str)));

    ck_assert_msg(net_family_is_ipv4(extra.family), "Expected family TOX_AF_INET (%d), got %u.", TOX_AF_INET,
                  extra.family.value);
    ck_assert_msg(extra.ip.v4.uint32 == loopback, "Expected 127.0.0.1, got %s.",
                  ip_ntoa(&ip, ip_str, sizeof(ip_str)));
#elif 0
    // TODO(iphydf): Fix this to work on IPv6-supporting systems.
    ck_assert_msg(net_family_is_ipv4(ip.family), "Expected family TOX_AF_INET (%d), got %u.", TOX_AF_INET, ip.family.value);
    ck_assert_msg(ip.ip.v4.uint32 == loopback, "Expected 127.0.0.1, got %s.",
                  ip_ntoa(&ip, ip_str, sizeof(ip_str)));
#endif
}
END_TEST

START_TEST(test_ip_equal)
{
    int res;
    IP ip1, ip2;
    ip_reset(&ip1);
    ip_reset(&ip2);

    res = ip_equal(nullptr, nullptr);
    ck_assert_msg(res == 0, "ip_equal(NULL, NULL): expected result 0, got %d.", res);

    res = ip_equal(&ip1, nullptr);
    ck_assert_msg(res == 0, "ip_equal(PTR, NULL): expected result 0, got %d.", res);

    res = ip_equal(nullptr, &ip1);
    ck_assert_msg(res == 0, "ip_equal(NULL, PTR): expected result 0, got %d.", res);

    ip1.family = net_family_ipv4;
    ip1.ip.v4.uint32 = net_htonl(0x7F000001);

    res = ip_equal(&ip1, &ip2);
    ck_assert_msg(res == 0, "ip_equal( {TOX_AF_INET, 127.0.0.1}, {TOX_AF_UNSPEC, 0} ): "
                  "expected result 0, got %d.", res);

    ip2.family = net_family_ipv4;
    ip2.ip.v4.uint32 = net_htonl(0x7F000001);

    res = ip_equal(&ip1, &ip2);
    ck_assert_msg(res != 0, "ip_equal( {TOX_AF_INET, 127.0.0.1}, {TOX_AF_INET, 127.0.0.1} ): "
                  "expected result != 0, got 0.");

    ip2.ip.v4.uint32 = net_htonl(0x7F000002);

    res = ip_equal(&ip1, &ip2);
    ck_assert_msg(res == 0, "ip_equal( {TOX_AF_INET, 127.0.0.1}, {TOX_AF_INET, 127.0.0.2} ): "
                  "expected result 0, got %d.", res);

    ip2.family = net_family_ipv6;
    ip2.ip.v6.uint32[0] = 0;
    ip2.ip.v6.uint32[1] = 0;
    ip2.ip.v6.uint32[2] = net_htonl(0xFFFF);
    ip2.ip.v6.uint32[3] = net_htonl(0x7F000001);

    ck_assert_msg(ipv6_ipv4_in_v6(ip2.ip.v6) != 0,
                  "ipv6_ipv4_in_v6(::ffff:127.0.0.1): expected != 0, got 0.");

    res = ip_equal(&ip1, &ip2);
    ck_assert_msg(res != 0, "ip_equal( {TOX_AF_INET, 127.0.0.1}, {TOX_AF_INET6, ::ffff:127.0.0.1} ): "
                  "expected result != 0, got 0.");

    IP6 ip6_loopback = get_ip6_loopback();
    memcpy(&ip2.ip.v6, &ip6_loopback, sizeof(IP6));
    res = ip_equal(&ip1, &ip2);
    ck_assert_msg(res == 0, "ip_equal( {TOX_AF_INET, 127.0.0.1}, {TOX_AF_INET6, ::1} ): expected result 0, got %d.", res);

    memcpy(&ip1, &ip2, sizeof(IP));
    res = ip_equal(&ip1, &ip2);
    ck_assert_msg(res != 0, "ip_equal( {TOX_AF_INET6, ::1}, {TOX_AF_INET6, ::1} ): expected result != 0, got 0.");

    ip2.ip.v6.uint8[15]++;
    res = ip_equal(&ip1, &ip2);
    ck_assert_msg(res == 0, "ip_equal( {TOX_AF_INET6, ::1}, {TOX_AF_INET6, ::2} ): expected result 0, got %d.", res);
}
END_TEST

static Suite *network_suite(void)
{
    Suite *s = suite_create("Network");

    networking_at_startup();

    DEFTESTCASE(addr_resolv_localhost);
    DEFTESTCASE(ip_equal);

    return s;
}

int main(void)
{
    setvbuf(stdout, nullptr, _IONBF, 0);

    Suite *network = network_suite();
    SRunner *test_runner = srunner_create(network);
    int number_failed = 0;

    srunner_run_all(test_runner, CK_NORMAL);
    number_failed = srunner_ntests_failed(test_runner);

    srunner_free(test_runner);

    return number_failed;
}
