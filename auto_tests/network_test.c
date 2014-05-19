#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <sys/types.h>
#include <stdint.h>
#include <string.h>
#include <check.h>
#include <stdlib.h>
#include <time.h>

#include "../toxcore/network.h"

START_TEST(test_addr_resolv_localhost)
{
#ifdef __CYGWIN__
    /* force initialization of network stack
     * normally this should happen automatically
     * cygwin doesn't do it for every network related function though
     * e.g. not for getaddrinfo... */
    socket(0, 0, 0);
    errno = 0;
#endif

    const char localhost[] = "localhost";
    int localhost_split = 0;

    IP ip;
    ip_init(&ip, 0);

    int res = addr_resolve(localhost, &ip, NULL);

    ck_assert_msg(res > 0, "Resolver failed: %u, %s (%x, %x)", errno, strerror(errno));

    if (res > 0) {
        ck_assert_msg(ip.family == AF_INET, "Expected family AF_INET, got %u.", ip.family);
        ck_assert_msg(ip.ip4.uint32 == htonl(0x7F000001), "Expected 127.0.0.1, got %s.", inet_ntoa(ip.ip4.in_addr));
    }

    ip_init(&ip, 1);
    res = addr_resolve(localhost, &ip, NULL);

    if (res < 1) {
        res = addr_resolve("ip6-localhost", &ip, NULL);
        localhost_split = 1;
    }

    ck_assert_msg(res > 0, "Resolver failed: %u, %s (%x, %x)", errno, strerror(errno));

    if (res > 0) {
        ck_assert_msg(ip.family == AF_INET6, "Expected family AF_INET6, got %u.", ip.family);
        ck_assert_msg(!memcmp(&ip.ip6, &in6addr_loopback, sizeof(IP6)), "Expected ::1, got %s.", ip_ntoa(&ip));
    }

    if (!localhost_split) {
        ip_init(&ip, 1);
        ip.family = AF_UNSPEC;
        IP extra;
        ip_reset(&extra);
        res = addr_resolve(localhost, &ip, &extra);
        ck_assert_msg(res > 0, "Resolver failed: %u, %s (%x, %x)", errno, strerror(errno));

        if (res > 0) {
            ck_assert_msg(ip.family == AF_INET6, "Expected family AF_INET6, got %u.", ip.family);
            ck_assert_msg(!memcmp(&ip.ip6, &in6addr_loopback, sizeof(IP6)), "Expected ::1, got %s.", ip_ntoa(&ip));

            ck_assert_msg(extra.family == AF_INET, "Expected family AF_INET, got %u.", extra.family);
            ck_assert_msg(extra.ip4.uint32 == htonl(0x7F000001), "Expected 127.0.0.1, got %s.", inet_ntoa(extra.ip4.in_addr));
        }
    } else {
        printf("Localhost seems to be split in two.\n");
    }
}
END_TEST

START_TEST(test_ip_equal)
{
    int res;
    IP ip1, ip2;
    ip_reset(&ip1);
    ip_reset(&ip2);

    res = ip_equal(NULL, NULL);
    ck_assert_msg(res == 0, "ip_equal(NULL, NULL): expected result 0, got %u.", res);

    res = ip_equal(&ip1, NULL);
    ck_assert_msg(res == 0, "ip_equal(PTR, NULL): expected result 0, got %u.", res);

    res = ip_equal(NULL, &ip1);
    ck_assert_msg(res == 0, "ip_equal(NULL, PTR): expected result 0, got %u.", res);

    ip1.family = AF_INET;
    ip1.ip4.uint32 = htonl(0x7F000001);

    res = ip_equal(&ip1, &ip2);
    ck_assert_msg(res == 0, "ip_equal( {AF_INET, 127.0.0.1}, {AF_UNSPEC, 0} ): expected result 0, got %u.", res);

    ip2.family = AF_INET;
    ip2.ip4.uint32 = htonl(0x7F000001);

    res = ip_equal(&ip1, &ip2);
    ck_assert_msg(res != 0, "ip_equal( {AF_INET, 127.0.0.1}, {AF_INET, 127.0.0.1} ): expected result != 0, got 0.");

    ip2.ip4.uint32 = htonl(0x7F000002);

    res = ip_equal(&ip1, &ip2);
    ck_assert_msg(res == 0, "ip_equal( {AF_INET, 127.0.0.1}, {AF_INET, 127.0.0.2} ): expected result 0, got %u.", res);

    ip2.family = AF_INET6;
    ip2.ip6.uint32[0] = 0;
    ip2.ip6.uint32[1] = 0;
    ip2.ip6.uint32[2] = htonl(0xFFFF);
    ip2.ip6.uint32[3] = htonl(0x7F000001);

    ck_assert_msg(IN6_IS_ADDR_V4MAPPED(&ip2.ip6.in6_addr) != 0,
                  "IN6_IS_ADDR_V4MAPPED(::ffff:127.0.0.1): expected != 0, got 0.");

    res = ip_equal(&ip1, &ip2);
    ck_assert_msg(res != 0, "ip_equal( {AF_INET, 127.0.0.1}, {AF_INET6, ::ffff:127.0.0.1} ): expected result != 0, got 0.");

    memcpy(&ip2.ip6, &in6addr_loopback, sizeof(IP6));
    res = ip_equal(&ip1, &ip2);
    ck_assert_msg(res == 0, "ip_equal( {AF_INET, 127.0.0.1}, {AF_INET6, ::1} ): expected result 0, got %u.", res);

    memcpy(&ip1, &ip2, sizeof(IP));
    res = ip_equal(&ip1, &ip2);
    ck_assert_msg(res != 0, "ip_equal( {AF_INET6, ::1}, {AF_INET6, ::1} ): expected result != 0, got 0.");

    ip2.ip6.uint8[15]++;
    res = ip_equal(&ip1, &ip2);
    ck_assert_msg(res == 0, "ip_equal( {AF_INET6, ::1}, {AF_INET6, ::2} ): expected result 0, got %res.", res);
}
END_TEST

START_TEST(test_struct_sizes)
{
    ck_assert_msg(sizeof(IP4) == 4, "sizeof(IP4): expected result 4, got %u.", sizeof(IP4));
    ck_assert_msg(sizeof(IP6) == 16, "sizeof(IP6): expected result 16, got %u.", sizeof(IP6));
    ck_assert_msg(sizeof(IP) == 17, "sizeof(IP): expected result 17, got %u.", sizeof(IP));
    ck_assert_msg(sizeof(IP_Port) == 19, "sizeof(IP_Port): expected result 19, got %u.", sizeof(IP_Port));
}
END_TEST

#define DEFTESTCASE(NAME) \
    TCase *tc_##NAME = tcase_create(#NAME); \
    tcase_add_test(tc_##NAME, test_##NAME); \
    suite_add_tcase(s, tc_##NAME);

Suite *network_suite(void)
{
    Suite *s = suite_create("Network");

    DEFTESTCASE(addr_resolv_localhost);
    DEFTESTCASE(ip_equal);
    DEFTESTCASE(struct_sizes);

    return s;
}

int main(int argc, char *argv[])
{
    srand((unsigned int) time(NULL));

    Suite *network = network_suite();
    SRunner *test_runner = srunner_create(network);
    int number_failed = 0;

    srunner_run_all(test_runner, CK_NORMAL);
    number_failed = srunner_ntests_failed(test_runner);

    srunner_free(test_runner);

    return number_failed;
}
