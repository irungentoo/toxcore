#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "check_compat.h"
#include "../testing/misc_tools.h"
#include "../toxcore/crypto_core.h"

#ifndef DHT_C_INCLUDED
#include "../toxcore/DHT.c"
#endif // DHT_C_INCLUDED
#include "../toxcore/tox.h"


// These tests currently fail.
static bool enable_broken_tests = false;

#ifndef USE_IPV6
#define USE_IPV6 1
#endif

static inline IP get_loopback()
{
    IP ip;
#if USE_IPV6
    ip.family = net_family_ipv6;
    ip.ip.v6 = get_ip6_loopback();
#else
    ip.family = net_family_ipv4;
    ip.ip.v4 = get_ip4_loopback();
#endif
    return ip;
}

static void mark_bad(const Mono_Time *mono_time, IPPTsPng *ipptp)
{
    ipptp->timestamp = mono_time_get(mono_time) - 2 * BAD_NODE_TIMEOUT;
    ipptp->hardening.routes_requests_ok = 0;
    ipptp->hardening.send_nodes_ok = 0;
    ipptp->hardening.testing_requests = 0;
}

static void mark_possible_bad(const Mono_Time *mono_time, IPPTsPng *ipptp)
{
    ipptp->timestamp = mono_time_get(mono_time);
    ipptp->hardening.routes_requests_ok = 0;
    ipptp->hardening.send_nodes_ok = 0;
    ipptp->hardening.testing_requests = 0;
}

static void mark_good(const Mono_Time *mono_time, IPPTsPng *ipptp)
{
    ipptp->timestamp = mono_time_get(mono_time);
    ipptp->hardening.routes_requests_ok = (HARDENING_ALL_OK >> 0) & 1;
    ipptp->hardening.send_nodes_ok = (HARDENING_ALL_OK >> 1) & 1;
    ipptp->hardening.testing_requests = (HARDENING_ALL_OK >> 2) & 1;
}

static void mark_all_good(const Mono_Time *mono_time, Client_data *list, uint32_t length, uint8_t ipv6)
{
    uint32_t i;

    for (i = 0; i < length; ++i) {
        if (ipv6) {
            mark_good(mono_time, &list[i].assoc6);
        } else {
            mark_good(mono_time, &list[i].assoc4);
        }
    }
}

/* Returns 1 if public_key has a furthest distance to comp_client_id
   than all public_key's  in the list */
static uint8_t is_furthest(const uint8_t *comp_client_id, Client_data *list, uint32_t length, const uint8_t *public_key)
{
    uint32_t i;

    for (i = 0; i < length; ++i) {
        if (id_closest(comp_client_id, public_key, list[i].public_key) == 1) {
            return 0;
        }
    }

    return 1;
}

static int client_in_list(Client_data *list, uint32_t length, const uint8_t *public_key)
{
    uint32_t i;

    for (i = 0; i < length; ++i) {
        if (id_equal(public_key, list[i].public_key)) {
            return i;
        }
    }

    return -1;
}

static void test_addto_lists_update(DHT            *dht,
                                    Client_data    *list,
                                    uint32_t        length,
                                    IP_Port        *ip_port)
{
    uint32_t used, test, test1, test2, found;
    IP_Port test_ipp;
    uint8_t test_id[CRYPTO_PUBLIC_KEY_SIZE];
    uint8_t ipv6 = net_family_is_ipv6(ip_port->ip.family) ? 1 : 0;

    // check id update for existing ip_port
    test = random_u32() % length;
    ipport_copy(&test_ipp, ipv6 ? &list[test].assoc6.ip_port : &list[test].assoc4.ip_port);

    random_bytes(test_id, sizeof(test_id));
    used = addto_lists(dht, test_ipp, test_id);
    ck_assert_msg(used >= 1, "Wrong number of added clients");
    // it is possible to have ip_port duplicates in the list, so ip_port @ found not always equal to ip_port @ test
    found = client_in_list(list, length, test_id);
    ck_assert_msg(found >= 0, "Client id is not in the list");
    ck_assert_msg(ipport_equal(&test_ipp, ipv6 ? &list[found].assoc6.ip_port : &list[found].assoc4.ip_port),
                  "Client IP_Port is incorrect");

    // check ip_port update for existing id
    test = random_u32() % length;
    test_ipp.port = random_u32() % TOX_PORT_DEFAULT;
    id_copy(test_id, list[test].public_key);

    used = addto_lists(dht, test_ipp, test_id);
    ck_assert_msg(used >= 1, "Wrong number of added clients");
    // it is not possible to have id duplicates in the list, so id @ found must be equal id @ test
    ck_assert_msg(client_in_list(list, length, test_id) == test, "Client id is not in the list");
    ck_assert_msg(ipport_equal(&test_ipp, ipv6 ? &list[test].assoc6.ip_port : &list[test].assoc4.ip_port),
                  "Client IP_Port is incorrect");

    // check ip_port update for existing id and ip_port (... port ... id ...)
    test1 = random_u32() % (length / 2);
    test2 = random_u32() % (length / 2) + length / 2;

    ipport_copy(&test_ipp, ipv6 ? &list[test1].assoc6.ip_port : &list[test1].assoc4.ip_port);
    id_copy(test_id, list[test2].public_key);

    if (ipv6) {
        list[test2].assoc6.ip_port.port = -1;
    } else {
        list[test2].assoc4.ip_port.port = -1;
    }

    used = addto_lists(dht, test_ipp, test_id);
    ck_assert_msg(used >= 1, "Wrong number of added clients");
    ck_assert_msg(client_in_list(list, length, test_id) == test2, "Client id is not in the list");
    ck_assert_msg(ipport_equal(&test_ipp, ipv6 ? &list[test2].assoc6.ip_port : &list[test2].assoc4.ip_port),
                  "Client IP_Port is incorrect");

    // check ip_port update for existing id and ip_port (... id ... port ...)
    test1 = random_u32() % (length / 2);
    test2 = random_u32() % (length / 2) + length / 2;

    ipport_copy(&test_ipp, ipv6 ? &list[test2].assoc6.ip_port : &list[test2].assoc4.ip_port);
    id_copy(test_id, list[test1].public_key);

    if (ipv6) {
        list[test1].assoc6.ip_port.port = -1;
    } else {
        list[test1].assoc4.ip_port.port = -1;
    }

    used = addto_lists(dht, test_ipp, test_id);
    ck_assert_msg(used >= 1, "Wrong number of added clients");
    ck_assert_msg(client_in_list(list, length, test_id) == test1, "Client id is not in the list");
    ck_assert_msg(ipport_equal(&test_ipp, ipv6 ? &list[test1].assoc6.ip_port : &list[test1].assoc4.ip_port),
                  "Client IP_Port is incorrect");
}

static void test_addto_lists_bad(DHT            *dht,
                                 Client_data    *list,
                                 uint32_t        length,
                                 IP_Port        *ip_port)
{
    // check "bad" clients replacement
    int used, test1, test2, test3;
    uint8_t public_key[CRYPTO_PUBLIC_KEY_SIZE], test_id1[CRYPTO_PUBLIC_KEY_SIZE], test_id2[CRYPTO_PUBLIC_KEY_SIZE],
            test_id3[CRYPTO_PUBLIC_KEY_SIZE];
    uint8_t ipv6 = net_family_is_ipv6(ip_port->ip.family) ? 1 : 0;

    random_bytes(public_key, sizeof(public_key));
    mark_all_good(dht->mono_time, list, length, ipv6);

    test1 = random_u32() % (length / 3);
    test2 = random_u32() % (length / 3) + length / 3;
    test3 = random_u32() % (length / 3) + 2 * length / 3;
    ck_assert_msg(!(test1 == test2 || test1 == test3 || test2 == test3), "Wrong test indices are chosen");

    id_copy((uint8_t *)&test_id1, list[test1].public_key);
    id_copy((uint8_t *)&test_id2, list[test2].public_key);
    id_copy((uint8_t *)&test_id3, list[test3].public_key);

    // mark nodes as "bad"
    if (ipv6) {
        mark_bad(dht->mono_time, &list[test1].assoc6);
        mark_bad(dht->mono_time, &list[test2].assoc6);
        mark_bad(dht->mono_time, &list[test3].assoc6);
    } else {
        mark_bad(dht->mono_time, &list[test1].assoc4);
        mark_bad(dht->mono_time, &list[test2].assoc4);
        mark_bad(dht->mono_time, &list[test3].assoc4);
    }

    ip_port->port += 1;
    used = addto_lists(dht, *ip_port, public_key);
    ck_assert_msg(used >= 1, "Wrong number of added clients");

    ck_assert_msg(client_in_list(list, length, public_key) >= 0, "Client id is not in the list");
    ck_assert_msg(client_in_list(list, length, test_id2) >= 0, "Wrong bad client removed");
    ck_assert_msg(client_in_list(list, length, test_id3) >= 0, "Wrong bad client removed");
}

static void test_addto_lists_possible_bad(DHT            *dht,
        Client_data    *list,
        uint32_t        length,
        IP_Port        *ip_port,
        const uint8_t  *comp_client_id)
{
    // check "possibly bad" clients replacement
    uint32_t used, test1, test2, test3;
    uint8_t public_key[CRYPTO_PUBLIC_KEY_SIZE], test_id1[CRYPTO_PUBLIC_KEY_SIZE], test_id2[CRYPTO_PUBLIC_KEY_SIZE],
            test_id3[CRYPTO_PUBLIC_KEY_SIZE];
    uint8_t ipv6 = net_family_is_ipv6(ip_port->ip.family) ? 1 : 0;

    random_bytes(public_key, sizeof(public_key));
    mark_all_good(dht->mono_time, list, length, ipv6);

    test1 = random_u32() % (length / 3);
    test2 = random_u32() % (length / 3) + length / 3;
    test3 = random_u32() % (length / 3) + 2 * length / 3;
    ck_assert_msg(!(test1 == test2 || test1 == test3 || test2 == test3), "Wrong test indices are chosen");

    id_copy((uint8_t *)&test_id1, list[test1].public_key);
    id_copy((uint8_t *)&test_id2, list[test2].public_key);
    id_copy((uint8_t *)&test_id3, list[test3].public_key);

    // mark nodes as "possibly bad"
    if (ipv6) {
        mark_possible_bad(dht->mono_time, &list[test1].assoc6);
        mark_possible_bad(dht->mono_time, &list[test2].assoc6);
        mark_possible_bad(dht->mono_time, &list[test3].assoc6);
    } else {
        mark_possible_bad(dht->mono_time, &list[test1].assoc4);
        mark_possible_bad(dht->mono_time, &list[test2].assoc4);
        mark_possible_bad(dht->mono_time, &list[test3].assoc4);
    }

    ip_port->port += 1;
    used = addto_lists(dht, *ip_port, public_key);
    ck_assert_msg(used >= 1, "Wrong number of added clients");

    ck_assert_msg(client_in_list(list, length, public_key) >= 0, "Client id is not in the list");

    bool inlist_id1 = client_in_list(list, length, test_id1) >= 0;
    bool inlist_id2 = client_in_list(list, length, test_id2) >= 0;
    bool inlist_id3 = client_in_list(list, length, test_id3) >= 0;

    ck_assert_msg(inlist_id1 + inlist_id2 + inlist_id3 == 2, "Wrong client removed");

    if (!inlist_id1) {
        ck_assert_msg(id_closest(comp_client_id, test_id2, test_id1) == 1,
                      "Id has been removed but is closer to than another one");
        ck_assert_msg(id_closest(comp_client_id, test_id3, test_id1) == 1,
                      "Id has been removed but is closer to than another one");
    } else if (!inlist_id2) {
        ck_assert_msg(id_closest(comp_client_id, test_id1, test_id2) == 1,
                      "Id has been removed but is closer to than another one");
        ck_assert_msg(id_closest(comp_client_id, test_id3, test_id2) == 1,
                      "Id has been removed but is closer to than another one");
    } else if (!inlist_id3) {
        ck_assert_msg(id_closest(comp_client_id, test_id1, test_id3) == 1,
                      "Id has been removed but is closer to than another one");
        ck_assert_msg(id_closest(comp_client_id, test_id2, test_id3) == 1,
                      "Id has been removed but is closer to than another one");
    }
}

static void test_addto_lists_good(DHT            *dht,
                                  Client_data    *list,
                                  uint32_t        length,
                                  IP_Port        *ip_port,
                                  const uint8_t  *comp_client_id)
{
    uint8_t public_key[CRYPTO_PUBLIC_KEY_SIZE];
    uint8_t ipv6 = net_family_is_ipv6(ip_port->ip.family) ? 1 : 0;

    mark_all_good(dht->mono_time, list, length, ipv6);

    // check "good" client id replacement
    do {
        random_bytes(public_key, sizeof(public_key));
    } while (is_furthest(comp_client_id, list, length, public_key));

    ip_port->port += 1;
    addto_lists(dht, *ip_port, public_key);
    ck_assert_msg(client_in_list(list, length, public_key) >= 0, "Good client id is not in the list");

    // check "good" client id skip
    do {
        random_bytes(public_key, sizeof(public_key));
    } while (!is_furthest(comp_client_id, list, length, public_key));

    ip_port->port += 1;
    addto_lists(dht, *ip_port, public_key);
    ck_assert_msg(client_in_list(list, length, public_key) == -1, "Good client id is in the list");
}

#ifndef MAX
#define MAX(a, b) ((a) > (b) ? (a) : (b))
#endif

static void test_addto_lists(IP ip)
{
    Logger *log = logger_new();
    uint32_t index = 1;
    logger_callback_log(log, (logger_cb *)print_debug_log, nullptr, &index);

    Mono_Time *mono_time = mono_time_new();
    ck_assert_msg(mono_time != nullptr, "Failed to create Mono_Time");

    Networking_Core *net = new_networking(log, ip, TOX_PORT_DEFAULT);
    ck_assert_msg(net != nullptr, "Failed to create Networking_Core");

    DHT *dht = new_dht(log, mono_time, net, true);
    ck_assert_msg(dht != nullptr, "Failed to create DHT");

    IP_Port ip_port;
    ip_port.ip = ip;
    ip_port.port = TOX_PORT_DEFAULT;
    uint8_t public_key[CRYPTO_PUBLIC_KEY_SIZE];
    uint16_t i, used;

    // check lists filling
    for (i = 0; i < MAX(LCLIENT_LIST, MAX_FRIEND_CLIENTS); ++i) {
        random_bytes(public_key, sizeof(public_key));
        used = addto_lists(dht, ip_port, public_key);
        ck_assert_msg(used == dht->num_friends + 1, "Wrong number of added clients with existing ip_port");
    }

    for (i = 0; i < MAX(LCLIENT_LIST, MAX_FRIEND_CLIENTS); ++i) {
        ip_port.port += 1;
        used = addto_lists(dht, ip_port, public_key);
        ck_assert_msg(used == dht->num_friends + 1, "Wrong number of added clients with existing public_key");
    }

    for (i = 0; i < MAX(LCLIENT_LIST, MAX_FRIEND_CLIENTS); ++i) {
        ip_port.port += 1;
        random_bytes(public_key, sizeof(public_key));
        used = addto_lists(dht, ip_port, public_key);
        ck_assert_msg(used >= 1, "Wrong number of added clients");
    }

    /*check: Current behavior if there are two clients with the same id is
     * to replace the first ip by the second. */
    test_addto_lists_update(dht, dht->close_clientlist, LCLIENT_LIST, &ip_port);

    for (i = 0; i < dht->num_friends; ++i) {
        test_addto_lists_update(dht, dht->friends_list[i].client_list, MAX_FRIEND_CLIENTS, &ip_port);
    }

    // check "bad" entries
    test_addto_lists_bad(dht, dht->close_clientlist, LCLIENT_LIST, &ip_port);

    for (i = 0; i < dht->num_friends; ++i) {
        test_addto_lists_bad(dht, dht->friends_list[i].client_list, MAX_FRIEND_CLIENTS, &ip_port);
    }

    // check "possibly bad" entries
    if (enable_broken_tests) {
        test_addto_lists_possible_bad(dht, dht->close_clientlist, LCLIENT_LIST, &ip_port, dht->self_public_key);

        for (i = 0; i < dht->num_friends; ++i) {
            test_addto_lists_possible_bad(dht, dht->friends_list[i].client_list, MAX_FRIEND_CLIENTS, &ip_port,
                                          dht->friends_list[i].public_key);
        }
    }

    // check "good" entries
    test_addto_lists_good(dht, dht->close_clientlist, LCLIENT_LIST, &ip_port, dht->self_public_key);

    for (i = 0; i < dht->num_friends; ++i) {
        test_addto_lists_good(dht, dht->friends_list[i].client_list, MAX_FRIEND_CLIENTS, &ip_port,
                              dht->friends_list[i].public_key);
    }

    kill_dht(dht);
    kill_networking(net);
    logger_kill(log);
}

static void test_addto_lists_ipv4(void)
{
    IP ip;
    ip_init(&ip, 0);
    test_addto_lists(ip);
}

static void test_addto_lists_ipv6(void)
{
    IP ip;
    ip_init(&ip, 1);
    test_addto_lists(ip);
}

#define DHT_DEFAULT_PORT (TOX_PORT_DEFAULT + 1000)

static void print_pk(uint8_t *public_key)
{
    uint32_t j;

    for (j = 0; j < CRYPTO_PUBLIC_KEY_SIZE; j++) {
        printf("%02X", public_key[j]);
    }

    printf("\n");
}

static void test_add_to_list(uint8_t cmp_list[][CRYPTO_PUBLIC_KEY_SIZE + 1],
                             uint16_t length, const uint8_t *pk,
                             const uint8_t *cmp_pk)
{
    uint8_t p_b[CRYPTO_PUBLIC_KEY_SIZE];
    uint16_t i;

    for (i = 0; i < length; ++i) {
        if (!cmp_list[i][CRYPTO_PUBLIC_KEY_SIZE]) {
            memcpy(cmp_list[i], pk, CRYPTO_PUBLIC_KEY_SIZE);
            cmp_list[i][CRYPTO_PUBLIC_KEY_SIZE] = 1;
            return;
        }

        if (memcmp(cmp_list[i], pk, CRYPTO_PUBLIC_KEY_SIZE) == 0) {
            return;
        }
    }

    for (i = 0; i < length; ++i) {
        if (id_closest(cmp_pk, cmp_list[i], pk) == 2) {
            memcpy(p_b, cmp_list[i], CRYPTO_PUBLIC_KEY_SIZE);
            memcpy(cmp_list[i], pk, CRYPTO_PUBLIC_KEY_SIZE);
            test_add_to_list(cmp_list, length, p_b, cmp_pk);
            break;
        }
    }
}

#define NUM_DHT 100

static void test_list_main(void)
{
    DHT *dhts[NUM_DHT];
    Logger *logs[NUM_DHT];
    Mono_Time *mono_times[NUM_DHT];
    uint32_t index[NUM_DHT];

    uint8_t cmp_list1[NUM_DHT][MAX_FRIEND_CLIENTS][CRYPTO_PUBLIC_KEY_SIZE + 1];
    memset(cmp_list1, 0, sizeof(cmp_list1));

    uint16_t i, j, k, l;

    for (i = 0; i < NUM_DHT; ++i) {
        IP ip;
        ip_init(&ip, 1);

        logs[i] = logger_new();
        index[i] = i + 1;
        logger_callback_log(logs[i], (logger_cb *)print_debug_log, nullptr, &index[i]);

        mono_times[i] = mono_time_new();

        dhts[i] = new_dht(logs[i], mono_times[i], new_networking(logs[i], ip, DHT_DEFAULT_PORT + i), true);
        ck_assert_msg(dhts[i] != nullptr, "Failed to create dht instances %u", i);
        ck_assert_msg(net_port(dhts[i]->net) != DHT_DEFAULT_PORT + i,
                      "Bound to wrong port: %d", net_port(dhts[i]->net));
    }

    for (i = 0; i < NUM_DHT; ++i) {
        for (j = 1; j < NUM_DHT; ++j) {
            test_add_to_list(cmp_list1[i], MAX_FRIEND_CLIENTS, dhts[(i + j) % NUM_DHT]->self_public_key, dhts[i]->self_public_key);
        }
    }

    for (i = 0; i < NUM_DHT; ++i) {
        for (j = 0; j < NUM_DHT; ++j) {
            if (i == j) {
                continue;
            }

            IP_Port ip_port;
            ip_init(&ip_port.ip, 0);
            ip_port.ip.ip.v4.uint32 = random_u32();
            ip_port.port = random_u32() % (UINT16_MAX - 1);
            ++ip_port.port;
            addto_lists(dhts[i], ip_port, dhts[j]->self_public_key);
        }
    }

#if 0
    print_pk(dhts[0]->self_public_key);

    for (i = 0; i < MAX_FRIEND_CLIENTS; ++i) {
        printf("----Entry %u----\n", i);

        print_pk(cmp_list1[i]);
    }

#endif
    uint16_t m_count = 0;

    for (l = 0; l < NUM_DHT; ++l) {
        for (i = 0; i < MAX_FRIEND_CLIENTS; ++i) {
            for (j = 1; j < NUM_DHT; ++j) {
                if (memcmp(cmp_list1[l][i], dhts[(l + j) % NUM_DHT]->self_public_key, CRYPTO_PUBLIC_KEY_SIZE) != 0) {
                    continue;
                }

                uint16_t count = 0;

                for (k = 0; k < LCLIENT_LIST; ++k) {
                    if (memcmp(dhts[l]->self_public_key, dhts[(l + j) % NUM_DHT]->close_clientlist[k].public_key,
                               CRYPTO_PUBLIC_KEY_SIZE) == 0) {
                        ++count;
                    }
                }

                if (count != 1) {
                    print_pk(dhts[l]->self_public_key);

                    for (k = 0; k < MAX_FRIEND_CLIENTS; ++k) {
                        printf("----Entry %u----\n", k);

                        print_pk(cmp_list1[l][k]);
                    }

                    for (k = 0; k < LCLIENT_LIST; ++k) {
                        printf("----Closel %u----\n", k);
                        print_pk(dhts[(l + j) % NUM_DHT]->close_clientlist[k].public_key);
                    }

                    print_pk(dhts[(l + j) % NUM_DHT]->self_public_key);
                }

                ck_assert_msg(count == 1, "Nodes in search don't know ip of friend. %u %u %u", i, j, count);

                Node_format ln[MAX_SENT_NODES];
                uint16_t n = get_close_nodes(dhts[(l + j) % NUM_DHT], dhts[l]->self_public_key, ln, net_family_unspec, 1, 0);
                ck_assert_msg(n == MAX_SENT_NODES, "bad num close %u | %u %u", n, i, j);

                count = 0;

                for (k = 0; k < MAX_SENT_NODES; ++k) {
                    if (memcmp(dhts[l]->self_public_key, ln[k].public_key, CRYPTO_PUBLIC_KEY_SIZE) == 0) {
                        ++count;
                    }
                }

                ck_assert_msg(count == 1, "Nodes in search don't know ip of friend. %u %u %u", i, j, count);
#if 0

                for (k = 0; k < MAX_SENT_NODES; ++k) {
                    printf("----gn %u----\n", k);
                    print_pk(ln[k].public_key);
                }

#endif
                ++m_count;
            }
        }
    }

    ck_assert_msg(m_count == (NUM_DHT) * (MAX_FRIEND_CLIENTS), "Bad count. %u != %u", m_count,
                  (NUM_DHT) * (MAX_FRIEND_CLIENTS));

    for (i = 0; i < NUM_DHT; ++i) {
        Networking_Core *n = dhts[i]->net;
        kill_dht(dhts[i]);
        kill_networking(n);
        mono_time_free(mono_times[i]);
        logger_kill(logs[i]);
    }
}


static void test_list(void)
{
    uint8_t i;

    for (i = 0; i < 10; ++i) {
        test_list_main();
    }
}

static void ip_callback(void *data, int32_t number, IP_Port ip_port)
{
}

#define NUM_DHT_FRIENDS 20

static uint64_t get_clock_callback(void *user_data)
{
    return *(uint64_t *)user_data;
}

static void test_DHT_test(void)
{
    uint32_t to_comp = 8394782;
    DHT *dhts[NUM_DHT];
    Logger *logs[NUM_DHT];
    Mono_Time *mono_times[NUM_DHT];
    uint64_t clock[NUM_DHT];
    uint32_t index[NUM_DHT];

    uint32_t i, j;

    for (i = 0; i < NUM_DHT; ++i) {
        IP ip;
        ip_init(&ip, 1);

        logs[i] = logger_new();
        index[i] = i + 1;
        logger_callback_log(logs[i], (logger_cb *)print_debug_log, nullptr, &index[i]);

        mono_times[i] = mono_time_new();
        clock[i] = current_time_monotonic(mono_times[i]);
        mono_time_set_current_time_callback(mono_times[i], get_clock_callback, &clock[i]);

        dhts[i] = new_dht(logs[i], mono_times[i], new_networking(logs[i], ip, DHT_DEFAULT_PORT + i), true);
        ck_assert_msg(dhts[i] != nullptr, "Failed to create dht instances %u", i);
        ck_assert_msg(net_port(dhts[i]->net) != DHT_DEFAULT_PORT + i, "Bound to wrong port");
    }

    struct {
        uint16_t tox1;
        uint16_t tox2;
    } pairs[NUM_DHT_FRIENDS];

    for (i = 0; i < NUM_DHT_FRIENDS; ++i) {
        // TODO(hugbubby): remove use of goto.
loop_top:
        pairs[i].tox1 = random_u32() % NUM_DHT;
        pairs[i].tox2 = (pairs[i].tox1 + (random_u32() % (NUM_DHT - 1)) + 1) % NUM_DHT;

        for (j = 0; j < i; ++j) {
            if (pairs[j].tox2 == pairs[i].tox2 && pairs[j].tox1 == pairs[i].tox1) {
                goto loop_top;
            }
        }

        uint16_t lock_count = 0;
        ck_assert_msg(dht_addfriend(dhts[pairs[i].tox2], dhts[pairs[i].tox1]->self_public_key, &ip_callback, &to_comp, 1337,
                                    &lock_count) == 0, "Failed to add friend");
        ck_assert_msg(lock_count == 1, "bad lock count: %u %u", lock_count, i);
    }

    for (i = 0; i < NUM_DHT; ++i) {
        IP_Port ip_port;
        ip_port.ip = get_loopback();
        ip_port.port = net_htons(DHT_DEFAULT_PORT + i);
        dht_bootstrap(dhts[(i - 1) % NUM_DHT], ip_port, dhts[i]->self_public_key);
    }

    while (true) {
        uint16_t counter = 0;

        for (i = 0; i < NUM_DHT_FRIENDS; ++i) {
            IP_Port a;

            if (dht_getfriendip(dhts[pairs[i].tox2], dhts[pairs[i].tox1]->self_public_key, &a) == 1) {
                ++counter;
            }
        }

        if (counter == NUM_DHT_FRIENDS) {
            break;
        }

        for (i = 0; i < NUM_DHT; ++i) {
            mono_time_update(mono_times[i]);
            networking_poll(dhts[i]->net, nullptr);
            do_dht(dhts[i]);
            clock[i] += 500;
        }

        c_sleep(20);
    }

    for (i = 0; i < NUM_DHT; ++i) {
        Networking_Core *n = dhts[i]->net;
        kill_dht(dhts[i]);
        kill_networking(n);
        mono_time_free(mono_times[i]);
        logger_kill(logs[i]);
    }
}

static void test_dht_create_packet(void)
{
    uint8_t plain[100] = {0};
    uint8_t pkt[1 + CRYPTO_PUBLIC_KEY_SIZE + CRYPTO_NONCE_SIZE + sizeof(plain) + CRYPTO_MAC_SIZE];

    uint8_t key[CRYPTO_SYMMETRIC_KEY_SIZE];
    new_symmetric_key(key);

    uint16_t length = dht_create_packet(key, key, NET_PACKET_GET_NODES, plain, sizeof(plain), pkt);

    ck_assert_msg(pkt[0] == NET_PACKET_GET_NODES, "Malformed packet.");
    ck_assert_msg(memcmp(pkt + 1, key, CRYPTO_SYMMETRIC_KEY_SIZE) == 0, "Malformed packet.");
    ck_assert_msg(length == 1 + CRYPTO_PUBLIC_KEY_SIZE + CRYPTO_NONCE_SIZE + sizeof(plain) + CRYPTO_MAC_SIZE,
                  "Invalid size. Should be %u got %d", (unsigned)sizeof(pkt), length);

    printf("Create Packet Successful!\n");
}

#define MAX_COUNT 3

static void dht_pack_unpack(const Node_format *nodes, size_t size, uint8_t *data, size_t length)
{
    int16_t packed_size = pack_nodes(data, length, nodes, size);
    ck_assert_msg(packed_size != -1, "Wrong pack_nodes result");

    uint16_t processed = 0;
    VLA(Node_format, nodes_unpacked, size);
    const uint8_t tcp_enabled = 1;

    uint16_t unpacked_count = unpack_nodes(nodes_unpacked, size, &processed, data, length, tcp_enabled);
    ck_assert_msg(unpacked_count == size, "Wrong unpack_nodes result");
    ck_assert_msg(processed == packed_size, "unpack_nodes did not process all data");

    for (size_t i = 0; i < size; i++) {
        const IP_Port *ipp1 = &nodes[i].ip_port;
        const IP_Port *ipp2 = &nodes_unpacked[i].ip_port;
        ck_assert_msg(ip_equal(&ipp1->ip, &ipp2->ip), "Unsuccessful ip unpack");
        ck_assert_msg(ipp1->port == ipp2->port, "Unsuccessful port unpack");

        const uint8_t *pk1 = nodes[i].public_key;
        const uint8_t *pk2 = nodes_unpacked[i].public_key;
        ck_assert_msg(!memcmp(pk1, pk2, CRYPTO_PUBLIC_KEY_SIZE), "Unsuccessful pk unpack");
    }
}

static void random_ip(IP_Port *ipp, int family)
{
    uint8_t *ip = nullptr;
    size_t size;

    if (family == TOX_AF_INET || family == TCP_INET) {
        ip = (uint8_t *)&ipp->ip.ip.v4;
        size = sizeof(ipp->ip.ip.v4);
    } else if (family == TOX_AF_INET6 || family == TCP_INET6) {
        ip = (uint8_t *)&ipp->ip.ip.v6;
        size = sizeof(ipp->ip.ip.v6);
    } else {
        return;
    }

    uint8_t *port = (uint8_t *)&ipp->port;
    random_bytes(port, sizeof(ipp->port));
    random_bytes(ip, size);
    // TODO(iphydf): Pass the net_family variant to random_ip.
    ipp->ip.family.value = family;
}

#define PACKED_NODES_SIZE (SIZE_IPPORT + CRYPTO_PUBLIC_KEY_SIZE)

static void test_dht_node_packing(void)
{
    const uint16_t length = MAX_COUNT * PACKED_NODES_SIZE;
    uint8_t *data = (uint8_t *)malloc(length);

    Node_format nodes[MAX_COUNT];
    const size_t pk_size = sizeof(nodes[0].public_key);

    random_bytes(nodes[0].public_key, pk_size);
    random_bytes(nodes[1].public_key, pk_size);
    random_bytes(nodes[2].public_key, pk_size);

    random_ip(&nodes[0].ip_port, TOX_AF_INET);
    random_ip(&nodes[1].ip_port, TOX_AF_INET);
    random_ip(&nodes[2].ip_port, TOX_AF_INET);
    dht_pack_unpack(nodes, 3, data, length);

    random_ip(&nodes[0].ip_port, TOX_AF_INET);
    random_ip(&nodes[1].ip_port, TOX_AF_INET);
    random_ip(&nodes[2].ip_port, TCP_INET);
    dht_pack_unpack(nodes, 3, data, length);

    random_ip(&nodes[0].ip_port, TOX_AF_INET);
    random_ip(&nodes[1].ip_port, TOX_AF_INET6);
    random_ip(&nodes[2].ip_port, TCP_INET6);
    dht_pack_unpack(nodes, 3, data, length);

    random_ip(&nodes[0].ip_port, TCP_INET);
    random_ip(&nodes[1].ip_port, TCP_INET6);
    random_ip(&nodes[2].ip_port, TCP_INET);
    dht_pack_unpack(nodes, 3, data, length);

    random_ip(&nodes[0].ip_port, TOX_AF_INET6);
    random_ip(&nodes[1].ip_port, TOX_AF_INET6);
    random_ip(&nodes[2].ip_port, TOX_AF_INET6);
    dht_pack_unpack(nodes, 3, data, length);

    free(data);
}

int main(void)
{
    setvbuf(stdout, nullptr, _IONBF, 0);

    test_dht_create_packet();
    test_dht_node_packing();

    test_list();
    test_DHT_test();

    if (enable_broken_tests) {
        test_addto_lists_ipv4();
        test_addto_lists_ipv6();
    }

    return 0;
}
