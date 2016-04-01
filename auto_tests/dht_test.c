#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <sys/param.h>
#include <time.h>

#include "../toxcore/tox.h"
#include "../toxcore/DHT.c"

#include "helpers.h"

#define swap(x,y) do \
   { unsigned char swap_temp[sizeof(x) == sizeof(y) ? (signed)sizeof(x) : -1]; \
     memcpy(swap_temp,&y,sizeof(x)); \
     memcpy(&y,&x,       sizeof(x)); \
     memcpy(&x,swap_temp,sizeof(x)); \
    } while(0)



/* Returns 1 if public_key has a furthest distance to comp_client_id
   than all public_key's  in the list */
uint8_t is_furthest(const uint8_t *comp_client_id, Client_data *list, uint32_t length, const uint8_t *public_key)
{
    uint32_t i;

    for (i = 0; i < length; ++i)
        if (id_closest(comp_client_id, public_key, list[i].public_key) == 1)
            return 0;

    return 1;
}



#define DHT_DEFAULT_PORT (TOX_PORT_DEFAULT + 20)

#define DHT_LIST_LENGTH 128

void print_pk(uint8_t *public_key)
{
    uint32_t j;

    for (j = 0; j < crypto_box_PUBLICKEYBYTES; j++) {
        printf("%02hhX", public_key[j]);
    }

    printf("\n");
}

void test_add_to_list(uint8_t cmp_list[][crypto_box_PUBLICKEYBYTES + 1], unsigned int length, const uint8_t *pk,
                      const uint8_t *cmp_pk)
{
    uint8_t p_b[crypto_box_PUBLICKEYBYTES];
    unsigned int i;

    for (i = 0; i < length; ++i) {
        if (!cmp_list[i][crypto_box_PUBLICKEYBYTES]) {
            memcpy(cmp_list[i], pk, crypto_box_PUBLICKEYBYTES);
            cmp_list[i][crypto_box_PUBLICKEYBYTES] = 1;
            return;
        } else {
            if (memcmp(cmp_list[i], pk, crypto_box_PUBLICKEYBYTES) == 0) {
                return;
            }
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

void test_list_main()
{
    /*
       DHT *dhts[NUM_DHT];

       uint8_t cmp_list1[NUM_DHT][MAX_FRIEND_CLIENTS][crypto_box_PUBLICKEYBYTES + 1];
       memset(cmp_list1, 0, sizeof(cmp_list1));

       IP ip;
       ip_init(&ip, 1);

       unsigned int i, j, k, l;

       for (i = 0; i < NUM_DHT; ++i) {
           IP ip;
           ip_init(&ip, 1);

           dhts[i] = new_DHT(new_networking(ip, DHT_DEFAULT_PORT + i));
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
               if (i == j)
                   continue;

               IP_Port ip_port;
               ip_init(&ip_port.ip, 0);
               ip_port.ip.ip4.uint32 = rand();
               ip_port.port = rand() % (UINT16_MAX - 1);
               ++ip_port.port;
               addto_lists(dhts[j], ip_port, dhts[i]->self_public_key);
           }
       }
    */
    /*
        print_pk(dhts[0]->self_public_key);

        for (i = 0; i < MAX_FRIEND_CLIENTS; ++i) {
            printf("----Entry %u----\n", i);

            print_pk(cmp_list1[i]);
        }
    *//*
unsigned int m_count = 0;

for (l = 0; l < NUM_DHT; ++l) {
for (i = 0; i < MAX_FRIEND_CLIENTS; ++i) {
    for (j = 1; j < NUM_DHT; ++j) {
        if (memcmp(cmp_list1[l][i], dhts[(l + j) % NUM_DHT]->self_public_key, crypto_box_PUBLICKEYBYTES) != 0)
            continue;

        unsigned int count = 0;

        for (k = 0; k < LCLIENT_LIST; ++k) {
            if (memcmp(dhts[l]->self_public_key, dhts[(l + j) % NUM_DHT]->close_clientlist[k].public_key,
                       crypto_box_PUBLICKEYBYTES) == 0)
                ++count;
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
            if (memcmp(dhts[l]->self_public_key, ln[k].public_key, crypto_box_PUBLICKEYBYTES) == 0)
                ++count;
        }

        ck_assert_msg(count == 1, "Nodes in search don't know ip of friend. %u %u %u", i, j, count);*/
    /*
                for (k = 0; k < MAX_SENT_NODES; ++k) {
                    printf("----gn %u----\n", k);
                    print_pk(ln[k].public_key);
                }*//*
++m_count;
}
}
}

ck_assert_msg(m_count == (NUM_DHT) * (MAX_FRIEND_CLIENTS), "Bad count. %u != %u", m_count,
(NUM_DHT) * (MAX_FRIEND_CLIENTS));

for (i = 0; i < NUM_DHT; ++i) {
void *n = dhts[i]->net;
kill_DHT(dhts[i]);
kill_networking(n);
}
*/
}


START_TEST(test_list)
{
    unsigned int i;

    for (i = 0; i < 10; ++i)
        test_list_main();
}
END_TEST

void ip_callback(void *data, int32_t number, IP_Port ip_port)
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

        dhts[i] = new_DHT(new_networking(ip, DHT_DEFAULT_PORT + i));
        ck_assert_msg(dhts[i] != 0, "Failed to create dht instances %u", i);
        ck_assert_msg(dhts[i]->net->port == htons(DHT_DEFAULT_PORT + i), "Bound to wrong port %u != %u", dhts[i]->net->port,
                      DHT_DEFAULT_PORT + i);
    }

    struct {
        uint16_t tox1;
        uint16_t tox2;
    } pairs[NUM_DHT_FRIENDS];

    uint8_t address[TOX_ADDRESS_SIZE];

    unsigned int num_f = 0;

    for (i = 0; i < NUM_DHT_FRIENDS; ++i) {
loop_top:
        pairs[i].tox1 = rand() % NUM_DHT;
        pairs[i].tox2 = (pairs[i].tox1 + (rand() % (NUM_DHT - 1)) + 1) % NUM_DHT;

        for (j = 0; j < i; ++j) {
            if (pairs[j].tox2 == pairs[i].tox2 && pairs[j].tox1 == pairs[i].tox1)
                goto loop_top;
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

            if (DHT_getfriendip(dhts[pairs[i].tox2], dhts[pairs[i].tox1]->self_public_key, &a) == 1)
                ++counter;
        }

        if (counter == NUM_DHT_FRIENDS) {
            break;
        }

        for (i = 0; i < NUM_DHT; ++i) {
            networking_poll(dhts[i]->net);
            do_DHT(dhts[i]);
        }

        c_sleep(500);
    }

    for (i = 0; i < NUM_DHT; ++i) {
        void *n = dhts[i]->net;
        kill_DHT(dhts[i]);
        kill_networking(n);
    }
}
END_TEST

Suite *dht_suite(void)
{
    Suite *s = suite_create("DHT");

    //DEFTESTCASE(addto_lists_ipv4);
    //DEFTESTCASE(addto_lists_ipv6);
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
    srunner_set_fork_status(test_runner, CK_NOFORK);
    srunner_run_all(test_runner, CK_NORMAL);
    number_failed = srunner_ntests_failed(test_runner);

    srunner_free(test_runner);

    return number_failed;
}
