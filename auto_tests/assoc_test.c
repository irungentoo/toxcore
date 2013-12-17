
#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#define AUTO_TEST
#include "../toxcore/DHT.h"
#include "../toxcore/assoc.h"
#include "../toxcore/util.h"

#include <sys/types.h>
#include <stdint.h>
#include <string.h>

#include <check.h>

START_TEST(test_basics)
{
    /* TODO: real test */
    uint8_t id[CLIENT_ID_SIZE];
    Assoc *assoc = new_Assoc_default(id);
    ck_assert_msg(assoc != NULL, "failed to create default assoc");

    kill_Assoc(assoc);
    assoc = new_Assoc(17, 4, id); /* results in an assoc of 16/3 */
    ck_assert_msg(assoc != NULL, "failed to create customized assoc");

    IP_Port ipp;
    ipp.ip.family = AF_INET;
    ipp.ip.ip4.uint8[0] = 1;
    ipp.port = htons(12345);

    IPPTs ippts_send;
    ippts_send.ip_port = ipp;
    ippts_send.timestamp = unix_time();
    IP_Port ipp_recv = ipp;

    uint8_t res = Assoc_add_entry(assoc, id, &ippts_send, &ipp_recv, 0);
    ck_assert_msg(res == 0, "stored self as entry: expected %u, got %u", 0, res);

    id[0]++;

    res = Assoc_add_entry(assoc, id, &ippts_send, &ipp_recv, 0);
    ck_assert_msg(res == 1, "failed to store entry: expected %u, got %u", 1, res);

    Assoc_close_entries close_entries;
    memset(&close_entries, 0, sizeof(close_entries));
    close_entries.count = 4;
    close_entries.count_good = 2;
    close_entries.wanted_id = id;

    Client_data *entries[close_entries.count];
    close_entries.result = entries;

    uint8_t found = Assoc_get_close_entries(assoc, &close_entries);
    ck_assert_msg(found == 1, "get_close_entries(): expected %u, got %u", 1, found);
}
END_TEST

START_TEST(test_fillup)
{
    /* TODO: real test */
    int i, j;
    uint8_t id[CLIENT_ID_SIZE];
    //uint32_t a = current_time();
    uint32_t a = 2710106197;
    srand(a);

    for (i = 0; i < CLIENT_ID_SIZE; ++i) {
        id[i] = rand();
    }

    Assoc *assoc = new_Assoc(6, 15, id);
    ck_assert_msg(assoc != NULL, "failed to create default assoc");
    struct entry {
        uint8_t id[CLIENT_ID_SIZE];
        IPPTs ippts_send;
        IP_Port ipp_recv;
    };
    unsigned int fail = 0;
    struct entry entries[128];
    struct entry closest[8];

    for (j = 0; j < 128; ++j) {

        for (i = 0; i < CLIENT_ID_SIZE; ++i) {
            entries[j].id[i] = rand();
        }

        IP_Port ipp;
        ipp.ip.family = AF_INET;
        ipp.ip.ip4.uint32 = rand();
        ipp.port = rand();
        entries[j].ippts_send.ip_port = ipp;
        entries[j].ippts_send.timestamp = unix_time();
        ipp.ip.ip4.uint32 = rand();
        ipp.port = rand();
        entries[j].ipp_recv = ipp;

        if (j % 16 == 0) {
            memcpy(entries[j].id, id, CLIENT_ID_SIZE - 30);
            memcpy(&closest[j / 16], &entries[j], sizeof(struct entry));

        }

        uint8_t res = Assoc_add_entry(assoc, entries[j].id, &entries[j].ippts_send, &entries[j].ipp_recv, 1);
        ck_assert_msg(res == 1, "failed to store entry: expected %u, got %u, j = %u", 1, res, j);
    }

    int good = 0;
    Assoc_close_entries close_entries;
    memset(&close_entries, 0, sizeof(close_entries));
    close_entries.count = 8;
    close_entries.count_good = 8;
    close_entries.wanted_id = id;

    Client_data *entri[close_entries.count];
    close_entries.result = entri;

    uint8_t found = Assoc_get_close_entries(assoc, &close_entries);
    ck_assert_msg(found == 8, "get_close_entries(): expected %u, got %u", 1, found);

    for (i = 0; i < 8; ++i) {
        for (j = 0; j < 8; ++j) {
            if (id_equal(entri[j]->client_id, closest[i].id))
                ++good;
        }
    }

    ck_assert_msg(good == 8, "Entries found were not the closest ones. Only %u/8 were.", good);
    //printf("good: %u %u %u\n", good, a, ((uint32_t)current_time() - a));
}
END_TEST

#define DEFTESTCASE(NAME) \
    TCase *tc_##NAME = tcase_create(#NAME); \
    tcase_add_test(tc_##NAME, test_##NAME); \
    suite_add_tcase(s, tc_##NAME);

#define DEFTESTCASE_SLOW(NAME, TIMEOUT) \
    DEFTESTCASE(NAME) \
    tcase_set_timeout(tc_##NAME, TIMEOUT);

Suite *Assoc_suite(void)
{
    Suite *s = suite_create("Assoc");

    DEFTESTCASE(basics);
    DEFTESTCASE(fillup);
    return s;
}

int main(int argc, char *argv[])
{
    unix_time_update();
    Suite *Assoc = Assoc_suite();
    SRunner *test_runner = srunner_create(Assoc);

    srunner_set_fork_status(test_runner, CK_NOFORK);

    srunner_run_all(test_runner, CK_NORMAL);

    int number_failed = srunner_ntests_failed(test_runner);

    srunner_free(test_runner);

    return number_failed;
}
