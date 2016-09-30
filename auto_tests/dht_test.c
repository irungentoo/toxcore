#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <sys/param.h>
#include <time.h>

#include "../toxcore/DHT.c"
#include "../toxcore/tox.h"

#include "helpers.h"


// These tests currently fail.
#if 0
#define swap(x,y) do \
   { unsigned char swap_temp[sizeof(x) == sizeof(y) ? (signed)sizeof(x) : -1]; \
     memcpy(swap_temp,&y,sizeof(x)); \
     memcpy(&y,&x,       sizeof(x)); \
     memcpy(&x,swap_temp,sizeof(x)); \
    } while(0)


static void mark_bad(IPPTsPng *ipptp)
{
    ipptp->timestamp = unix_time() - 2 * BAD_NODE_TIMEOUT;
    ipptp->hardening.routes_requests_ok = 0;
    ipptp->hardening.send_nodes_ok = 0;
    ipptp->hardening.testing_requests = 0;
}

static void mark_possible_bad(IPPTsPng *ipptp)
{
    ipptp->timestamp = unix_time();
    ipptp->hardening.routes_requests_ok = 0;
    ipptp->hardening.send_nodes_ok = 0;
    ipptp->hardening.testing_requests = 0;
}

static void mark_good(IPPTsPng *ipptp)
{
    ipptp->timestamp = unix_time();
    ipptp->hardening.routes_requests_ok = (HARDENING_ALL_OK >> 0) & 1;
    ipptp->hardening.send_nodes_ok = (HARDENING_ALL_OK >> 1) & 1;
    ipptp->hardening.testing_requests = (HARDENING_ALL_OK >> 2) & 1;
}

static void mark_all_good(Client_data *list, uint32_t length, uint8_t ipv6)
{
    uint32_t i;

    for (i = 0; i < length; ++i) {
        if (ipv6) {
            mark_good(&list[i].assoc6);
        } else {
            mark_good(&list[i].assoc4);
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
    int i;

    for (i = 0; i < (int)length; ++i) {
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
    int used, test, test1, test2, found;
    IP_Port test_ipp;
    uint8_t test_id[crypto_box_PUBLICKEYBYTES];
    uint8_t ipv6 = ip_port->ip.family == AF_INET6 ? 1 : 0;

    // check id update for existing ip_port
    test = rand() % length;
    ipport_copy(&test_ipp, ipv6 ? &list[test].assoc6.ip_port : &list[test].assoc4.ip_port);

    randombytes(test_id, sizeof(test_id));
    used = addto_lists(dht, test_ipp, test_id);
    ck_assert_msg(used >= 1, "Wrong number of added clients");
    // it is possible to have ip_port duplicates in the list, so ip_port @ found not always equal to ip_port @ test
    found = client_in_list(list, length, test_id);
    ck_assert_msg(found >= 0, "Client id is not in the list");
    ck_assert_msg(ipport_equal(&test_ipp, ipv6 ? &list[found].assoc6.ip_port : &list[found].assoc4.ip_port),
                  "Client IP_Port is incorrect");

    // check ip_port update for existing id
    test = rand() % length;
    test_ipp.port = rand() % TOX_PORT_DEFAULT;
    id_copy(test_id, list[test].public_key);

    used = addto_lists(dht, test_ipp, test_id);
    ck_assert_msg(used >= 1, "Wrong number of added clients");
    // it is not possible to have id duplicates in the list, so id @ found must be equal id @ test
    ck_assert_msg(client_in_list(list, length, test_id) == test, "Client id is not in the list");
    ck_assert_msg(ipport_equal(&test_ipp, ipv6 ? &list[test].assoc6.ip_port : &list[test].assoc4.ip_port),
                  "Client IP_Port is incorrect");

    // check ip_port update for existing id and ip_port (... port ... id ...)
    test1 = rand() % (length / 2);
    test2 = rand() % (length / 2) + length / 2;

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
    test1 = rand() % (length / 2);
    test2 = rand() % (length / 2) + length / 2;

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
    uint8_t public_key[crypto_box_PUBLICKEYBYTES], test_id1[crypto_box_PUBLICKEYBYTES], test_id2[crypto_box_PUBLICKEYBYTES],
            test_id3[crypto_box_PUBLICKEYBYTES];
    uint8_t ipv6 = ip_port->ip.family == AF_INET6 ? 1 : 0;

    randombytes(public_key, sizeof(public_key));
    mark_all_good(list, length, ipv6);

    test1 = rand() % (length / 3);
    test2 = rand() % (length / 3) + length / 3;
    test3 = rand() % (length / 3) + 2 * length / 3;
    ck_assert_msg(!(test1 == test2 || test1 == test3 || test2 == test3), "Wrong test indices are chosen");

    id_copy((uint8_t *)&test_id1, list[test1].public_key);
    id_copy((uint8_t *)&test_id2, list[test2].public_key);
    id_copy((uint8_t *)&test_id3, list[test3].public_key);

    // mark nodes as "bad"
    if (ipv6) {
        mark_bad(&list[test1].assoc6);
        mark_bad(&list[test2].assoc6);
        mark_bad(&list[test3].assoc6);
    } else {
        mark_bad(&list[test1].assoc4);
        mark_bad(&list[test2].assoc4);
        mark_bad(&list[test3].assoc4);
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
    int used, test1, test2, test3;
    uint8_t public_key[crypto_box_PUBLICKEYBYTES], test_id1[crypto_box_PUBLICKEYBYTES], test_id2[crypto_box_PUBLICKEYBYTES],
            test_id3[crypto_box_PUBLICKEYBYTES];
    uint8_t ipv6 = ip_port->ip.family == AF_INET6 ? 1 : 0;

    randombytes(public_key, sizeof(public_key));
    mark_all_good(list, length, ipv6);

    test1 = rand() % (length / 3);
    test2 = rand() % (length / 3) + length / 3;
    test3 = rand() % (length / 3) + 2 * length / 3;
    ck_assert_msg(!(test1 == test2 || test1 == test3 || test2 == test3), "Wrong test indices are chosen");

    id_copy((uint8_t *)&test_id1, list[test1].public_key);
    id_copy((uint8_t *)&test_id2, list[test2].public_key);
    id_copy((uint8_t *)&test_id3, list[test3].public_key);

    // mark nodes as "possibly bad"
    if (ipv6) {
        mark_possible_bad(&list[test1].assoc6);
        mark_possible_bad(&list[test2].assoc6);
        mark_possible_bad(&list[test3].assoc6);
    } else {
        mark_possible_bad(&list[test1].assoc4);
        mark_possible_bad(&list[test2].assoc4);
        mark_possible_bad(&list[test3].assoc4);
    }

    ip_port->port += 1;
    used = addto_lists(dht, *ip_port, public_key);
    ck_assert_msg(used >= 1, "Wrong number of added clients");

    ck_assert_msg(client_in_list(list, length, public_key) >= 0, "Client id is not in the list");

    int inlist_id1 = client_in_list(list, length, test_id1) >= 0;
    int inlist_id2 = client_in_list(list, length, test_id2) >= 0;
    int inlist_id3 = client_in_list(list, length, test_id3) >= 0;

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
    uint8_t public_key[crypto_box_PUBLICKEYBYTES];
    uint8_t ipv6 = ip_port->ip.family == AF_INET6 ? 1 : 0;

    mark_all_good(list, length, ipv6);

    // check "good" client id replacement
    do {
        randombytes(public_key, sizeof(public_key));
    } while (is_furthest(comp_client_id, list, length, public_key));

    ip_port->port += 1;
    addto_lists(dht, *ip_port, public_key);
    ck_assert_msg(client_in_list(list, length, public_key) >= 0, "Good client id is not in the list");

    // check "good" client id skip
    do {
        randombytes(public_key, sizeof(public_key));
    } while (!is_furthest(comp_client_id, list, length, public_key));

    ip_port->port += 1;
    addto_lists(dht, *ip_port, public_key);
    ck_assert_msg(client_in_list(list, length, public_key) == -1, "Good client id is in the list");
}

static void test_addto_lists(IP ip)
{
    Networking_Core *net = new_networking(NULL, ip, TOX_PORT_DEFAULT);
    ck_assert_msg(net != 0, "Failed to create Networking_Core");

    DHT *dht = new_DHT(NULL, net);
    ck_assert_msg(dht != 0, "Failed to create DHT");

    IP_Port ip_port = { .ip = ip, .port = TOX_PORT_DEFAULT };
    uint8_t public_key[crypto_box_PUBLICKEYBYTES];
    int i, used;

    // check lists filling
    for (i = 0; i < MAX(LCLIENT_LIST, MAX_FRIEND_CLIENTS); ++i) {
        randombytes(public_key, sizeof(public_key));
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
        randombytes(public_key, sizeof(public_key));
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
    /*
    test_addto_lists_possible_bad(dht, dht->close_clientlist, LCLIENT_LIST, &ip_port, dht->self_public_key);

    for (i = 0; i < dht->num_friends; ++i)
        test_addto_lists_possible_bad(dht, dht->friends_list[i].client_list, MAX_FRIEND_CLIENTS, &ip_port,
                                      dht->friends_list[i].public_key);
    */
    // check "good" entries
    test_addto_lists_good(dht, dht->close_clientlist, LCLIENT_LIST, &ip_port, dht->self_public_key);

    for (i = 0; i < dht->num_friends; ++i)
        test_addto_lists_good(dht, dht->friends_list[i].client_list, MAX_FRIEND_CLIENTS, &ip_port,
                              dht->friends_list[i].public_key);

    kill_DHT(dht);
    kill_networking(net);
}

START_TEST(test_addto_lists_ipv4)
{
    IP ip;
    ip_init(&ip, 0);
    test_addto_lists(ip);
}
END_TEST

START_TEST(test_addto_lists_ipv6)
{
    IP ip;
    ip_init(&ip, 1);
    test_addto_lists(ip);
}
END_TEST
#endif

#define DHT_DEFAULT_PORT (TOX_PORT_DEFAULT + 20)

#define DHT_LIST_LENGTH 128

static void print_pk(uint8_t *public_key)
{
    uint32_t j;

    for (j = 0; j < crypto_box_PUBLICKEYBYTES; j++) {
        printf("%02hhX", public_key[j]);
    }

    printf("\n");
}

static void test_add_to_list(uint8_t cmp_list[][crypto_box_PUBLICKEYBYTES + 1],
                             unsigned int length, const uint8_t *pk,
                             const uint8_t *cmp_pk)
{
    uint8_t p_b[crypto_box_PUBLICKEYBYTES];
    unsigned int i;

    for (i = 0; i < length; ++i) {
        if (!cmp_list[i][crypto_box_PUBLICKEYBYTES]) {
            memcpy(cmp_list[i], pk, crypto_box_PUBLICKEYBYTES);
            cmp_list[i][crypto_box_PUBLICKEYBYTES] = 1;
            return;
        }

        if (memcmp(cmp_list[i], pk, crypto_box_PUBLICKEYBYTES) == 0) {
            return;
        }
    }

    for (i = 0; i < length; ++i) {
        if (id_closest(cmp_pk, cmp_list[i], pk) == 2) {
            memcpy(p_b, cmp_list[i], crypto_box_PUBLICKEYBYTES);
            memcpy(cmp_list[i], pk, crypto_box_PUBLICKEYBYTES);
            test_add_to_list(cmp_list, length, p_b, cmp_pk);
            break;
        }
    }
}

#define NUM_DHT 100

static void test_list_main(void)
{
    DHT *dhts[NUM_DHT];

    uint8_t cmp_list1[NUM_DHT][MAX_FRIEND_CLIENTS][crypto_box_PUBLICKEYBYTES + 1];
    memset(cmp_list1, 0, sizeof(cmp_list1));

    unsigned int i, j, k, l;

    for (i = 0; i < NUM_DHT; ++i) {
        IP ip;
        ip_init(&ip, 1);

        dhts[i] = new_DHT(NULL, new_networking(NULL, ip, DHT_DEFAULT_PORT + i));
        ck_assert_msg(dhts[i] != 0, "Failed to create dht instances %u", i);
        ck_assert_msg(dhts[i]->net->port != DHT_DEFAULT_PORT + i, "Bound to wrong port");
    }

    for (j = 0; j < NUM_DHT; ++j) {
        for (i = 1; i < NUM_DHT; ++i) {
            test_add_to_list(cmp_list1[j], MAX_FRIEND_CLIENTS, dhts[(i + j) % NUM_DHT]->self_public_key, dhts[j]->self_public_key);
        }
    }

    for (j = 0; j < NUM_DHT; ++j) {
        for (i = 0; i < NUM_DHT; ++i) {
            if (i == j) {
                continue;
            }

            IP_Port ip_port;
            ip_init(&ip_port.ip, 0);
            ip_port.ip.ip4.uint32 = rand();
            ip_port.port = rand() % (UINT16_MAX - 1);
            ++ip_port.port;
            addto_lists(dhts[j], ip_port, dhts[i]->self_public_key);
        }
    }

    /*
        print_pk(dhts[0]->self_public_key);

        for (i = 0; i < MAX_FRIEND_CLIENTS; ++i) {
            printf("----Entry %u----\n", i);

            print_pk(cmp_list1[i]);
        }
    */
    unsigned int m_count = 0;

    for (l = 0; l < NUM_DHT; ++l) {
        for (i = 0; i < MAX_FRIEND_CLIENTS; ++i) {
            for (j = 1; j < NUM_DHT; ++j) {
                if (memcmp(cmp_list1[l][i], dhts[(l + j) % NUM_DHT]->self_public_key, crypto_box_PUBLICKEYBYTES) != 0) {
                    continue;
                }

                unsigned int count = 0;

                for (k = 0; k < LCLIENT_LIST; ++k) {
                    if (memcmp(dhts[l]->self_public_key, dhts[(l + j) % NUM_DHT]->close_clientlist[k].public_key,
                               crypto_box_PUBLICKEYBYTES) == 0) {
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
                int n = get_close_nodes(dhts[(l + j) % NUM_DHT], dhts[l]->self_public_key, ln, 0, 1, 0);
                ck_assert_msg(n == MAX_SENT_NODES, "bad num close %u | %u %u", n, i, j);

                count = 0;

                for (k = 0; k < MAX_SENT_NODES; ++k) {
                    if (memcmp(dhts[l]->self_public_key, ln[k].public_key, crypto_box_PUBLICKEYBYTES) == 0) {
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
        kill_DHT(dhts[i]);
        kill_networking(n);
    }
}


START_TEST(test_list)
{
    unsigned int i;

    for (i = 0; i < 10; ++i) {
        test_list_main();
    }
}
END_TEST

static void ip_callback(void *data, int32_t number, IP_Port ip_port)
{
}


#if defined(_WIN32) || defined(__WIN32__) || defined (WIN32)
#define c_sleep(x) Sleep(1*x)
#else
#include <unistd.h>
#define c_sleep(x) usleep(1000*x)
#endif

#define NUM_DHT_FRIENDS 20

START_TEST(test_DHT_test)
{
    uint32_t to_comp = 8394782;
    DHT *dhts[NUM_DHT];

    unsigned int i, j;

    for (i = 0; i < NUM_DHT; ++i) {
        IP ip;
        ip_init(&ip, 1);

        dhts[i] = new_DHT(NULL, new_networking(NULL, ip, DHT_DEFAULT_PORT + i));
        ck_assert_msg(dhts[i] != 0, "Failed to create dht instances %u", i);
        ck_assert_msg(dhts[i]->net->port != DHT_DEFAULT_PORT + i, "Bound to wrong port");
    }

    struct {
        uint16_t tox1;
        uint16_t tox2;
    } pairs[NUM_DHT_FRIENDS];

    for (i = 0; i < NUM_DHT_FRIENDS; ++i) {
loop_top:
        pairs[i].tox1 = rand() % NUM_DHT;
        pairs[i].tox2 = (pairs[i].tox1 + (rand() % (NUM_DHT - 1)) + 1) % NUM_DHT;

        for (j = 0; j < i; ++j) {
            if (pairs[j].tox2 == pairs[i].tox2 && pairs[j].tox1 == pairs[i].tox1) {
                goto loop_top;
            }
        }

        uint16_t lock_count = 0;
        ck_assert_msg(DHT_addfriend(dhts[pairs[i].tox2], dhts[pairs[i].tox1]->self_public_key, &ip_callback, &to_comp, 1337,
                                    &lock_count) == 0, "Failed to add friend");
        ck_assert_msg(lock_count == 1, "bad lock count: %u %u", lock_count, i);
    }

    for (i = 0; i < NUM_DHT; ++i) {
        IP_Port ip_port;
        ip_init(&ip_port.ip, 1);
        ip_port.ip.ip6.uint8[15] = 1;
        ip_port.port = htons(DHT_DEFAULT_PORT + i);
        DHT_bootstrap(dhts[(i - 1) % NUM_DHT], ip_port, dhts[i]->self_public_key);
    }

    while (1) {
        uint16_t counter = 0;

        for (i = 0; i < NUM_DHT_FRIENDS; ++i) {
            IP_Port a;

            if (DHT_getfriendip(dhts[pairs[i].tox2], dhts[pairs[i].tox1]->self_public_key, &a) == 1) {
                ++counter;
            }
        }

        if (counter == NUM_DHT_FRIENDS) {
            break;
        }

        for (i = 0; i < NUM_DHT; ++i) {
            networking_poll(dhts[i]->net, NULL);
            do_DHT(dhts[i]);
        }

        c_sleep(500);
    }

    for (i = 0; i < NUM_DHT; ++i) {
        Networking_Core *n = dhts[i]->net;
        kill_DHT(dhts[i]);
        kill_networking(n);
    }
}
END_TEST

static Suite *dht_suite(void)
{
    Suite *s = suite_create("DHT");

#if 0
    DEFTESTCASE(addto_lists_ipv4);
    DEFTESTCASE(addto_lists_ipv6);
#endif
    DEFTESTCASE_SLOW(list, 20);
    DEFTESTCASE_SLOW(DHT_test, 50);
    return s;
}

int main(int argc, char *argv[])
{
    srand((unsigned int) time(NULL));

    Suite *dht = dht_suite();
    SRunner *test_runner = srunner_create(dht);

    int number_failed = 0;
    //srunner_set_fork_status(test_runner, CK_NOFORK);
    srunner_run_all(test_runner, CK_NORMAL);
    number_failed = srunner_ntests_failed(test_runner);

    srunner_free(test_runner);

    return number_failed;
}
