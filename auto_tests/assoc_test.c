
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

typedef struct retvals_t {
    struct {
        size_t    calls;
        uint8_t   val;
    } new;
    struct {
        size_t    calls;
        uint32_t  client_pos;
        uint16_t  val;
    } usable;
    struct {
        size_t    calls;
        uint16_t  val;
    } usage;
    struct {
        size_t    calls;
    } bad;
    struct {
        size_t    calls;
        uint32_t  client_pos;
    } delete;
} retvals_t;

/* new association discovered             : returning 1 means "interested" */
uint8_t check_new_func(DHT_assoc *dhtassoc, void *data, uint32_t hash, uint8_t *client_id, uint8_t seen, IP_Port *ipp)
{
    retvals_t *retvals = data;
    retvals->new.calls++;
    return retvals->new.val;
}

uint16_t check_usable_callback(DHT_assoc *dhtassoc, void *data, uint32_t client_pos, Client_data *client)
{
    retvals_t *retvals = data;
    retvals->usable.calls++;
    retvals->usable.client_pos = client_pos;
    return retvals->usable.val;
}

uint16_t check_usage_callback(DHT_assoc *dhtassoc, void *data, uint32_t client_pos, Client_data *client)
{
    retvals_t *retvals = data;
    retvals->usage.calls++;
    return retvals->usage.val;
}

void check_bad_callback(DHT_assoc *dhtassoc, void *data, uint32_t client_pos, Client_data *client)
{
    retvals_t *retvals = data;
    retvals->bad.calls++;
}

void check_delete_callback(DHT_assoc *dhtassoc, void *data, uint32_t client_pos, Client_data *client)
{
    retvals_t *retvals = data;
    retvals->delete.client_pos = client_pos;
    retvals->delete.calls++;
}

/* positive value must be exactly met, negative sets a minimum to reach */
void check_stat(DHT_assoc_statistics *assoc_stat, ssize_t clients, ssize_t candidates, char *file, size_t line)
{
    if (clients >= 0)
        ck_assert_msg(assoc_stat->clients == (size_t)clients, "%s:%5d DHT_assoc #client: Expected %u, got %u.",
                      file, line, clients, assoc_stat->clients);
    else
        ck_assert_msg(assoc_stat->clients >= (size_t)(- clients),
                      "%s:%5d DHT_assoc #client: Expected at least %u, got only %u.",
                      file, line, - clients, assoc_stat->clients);

    if (candidates >= 0)
        ck_assert_msg(assoc_stat->candidates == (size_t)candidates, "%s:%5d DHT_assoc #candidates: Expected %u, got %u.",
                      file, line, candidates, assoc_stat->candidates);
    else
        ck_assert_msg(assoc_stat->candidates >= (size_t)(- candidates),
                      "%s:%5d DHT_assoc #candidates: Expected at least %u, got only %u.",
                      file, line, - candidates, assoc_stat->candidates);
}

DHT_assoc *init(retvals_t *retvals, DHT_assoc_callbacks *callbacks)
{
    DHT_assoc *dhtassoc = DHT_assoc_new(NULL);
    ck_assert_msg(dhtassoc != NULL, "Failed to create DHT_assoc structure.");

    memset(retvals, 0, sizeof(*retvals));

    callbacks->check_funcs.check_new_func = check_new_func;
    callbacks->check_funcs.check_usable_func = check_usable_callback;
    callbacks->check_funcs.check_usage_func = check_usage_callback;
    callbacks->check_funcs.check_bad_func = check_bad_callback;
    callbacks->check_funcs.check_delete_func = check_delete_callback;

    DHT_assoc_register_callback(dhtassoc, NULL, retvals, callbacks);

    DHT_assoc_statistics assoc_stat;

    DHT_assoc_calc_statistics(dhtassoc, &assoc_stat);
    ck_assert_msg(assoc_stat.handlers == 1, "DHT_assoc #handlers: Expected %u, got %u.",
                  1, assoc_stat.clients);
    check_stat(&assoc_stat, 0, 0, __FILE__, __LINE__);

    /* force artificial time */
    unix_time_force(0);

    return dhtassoc;
}

/* debugging output */
static uint8_t do_print = 0;

void progress_maybe(char *s, int l)
{
    if (do_print)
        fprintf(stderr, "%s: %4u\n", s, l);
}

void calls_maybe(retvals_t *retvals, int line)
{
    if (do_print)
        fprintf(stderr, "[%u] calls: %zu %zu %zu %zu %zu\n", line,
                retvals->new.calls, retvals->usable.calls, retvals->usage.calls,
                retvals->bad.calls, retvals->delete.calls);
}

START_TEST(test_new_unwanted_unseen)
{
    retvals_t retvals;
    DHT_assoc_callbacks callbacks;
    DHT_assoc *dhtassoc = init(&retvals, &callbacks);

    DHT_assoc_statistics assoc_stat;

    uint8_t id[CLIENT_ID_SIZE];
    id[1] = 1;

    IP_Port ipp;
    ipp.ip.ip4.uint8[0] = 200;
    ipp.ip.family = AF_INET;

    uint8_t seen = 0;

    DHT_assoc_candidate_new(dhtassoc, id, &ipp, seen);

    DHT_assoc_calc_statistics(dhtassoc, &assoc_stat);
    calls_maybe(&retvals, __LINE__);
    check_stat(&assoc_stat, 0, 1, __FILE__, __LINE__);

    ipp.ip.family = AF_INET6;
    DHT_assoc_candidate_new(dhtassoc, id, &ipp, seen);

    DHT_assoc_calc_statistics(dhtassoc, &assoc_stat);
    calls_maybe(&retvals, __LINE__);
    check_stat(&assoc_stat, 0, 1, __FILE__, __LINE__);

    ipp.ip.family = AF_INET;
    DHT_assoc_candidate_new(dhtassoc, id, &ipp, seen);

    DHT_assoc_calc_statistics(dhtassoc, &assoc_stat);
    calls_maybe(&retvals, __LINE__);
    check_stat(&assoc_stat, 0, 1, __FILE__, __LINE__);

    ipp.ip.family = AF_INET6;
    DHT_assoc_candidate_new(dhtassoc, id, &ipp, seen);

    DHT_assoc_calc_statistics(dhtassoc, &assoc_stat);
    calls_maybe(&retvals, __LINE__);
    check_stat(&assoc_stat, 0, 1, __FILE__, __LINE__);
}
END_TEST

START_TEST(test_new_wanted_unseen)
{
    retvals_t retvals;
    DHT_assoc_callbacks callbacks;
    DHT_assoc *dhtassoc = init(&retvals, &callbacks);

    DHT_assoc_statistics assoc_stat;

    retvals.new.val = 1;

    uint8_t id[CLIENT_ID_SIZE];
    id[1] = 1;

    IP_Port ipp;
    ipp.ip.ip4.uint8[0] = 200;
    ipp.ip.family = AF_INET;

    uint8_t seen = 0;

    DHT_assoc_candidate_new(dhtassoc, id, &ipp, seen);

    DHT_assoc_calc_statistics(dhtassoc, &assoc_stat);
    calls_maybe(&retvals, __LINE__);
    check_stat(&assoc_stat, 0, 1, __FILE__, __LINE__);

    ipp.ip.family = AF_INET6;
    DHT_assoc_candidate_new(dhtassoc, id, &ipp, seen);

    DHT_assoc_calc_statistics(dhtassoc, &assoc_stat);
    calls_maybe(&retvals, __LINE__);
    check_stat(&assoc_stat, 0, 1, __FILE__, __LINE__);

    ipp.ip.family = AF_INET;
    DHT_assoc_candidate_new(dhtassoc, id, &ipp, seen);

    DHT_assoc_calc_statistics(dhtassoc, &assoc_stat);
    calls_maybe(&retvals, __LINE__);
    check_stat(&assoc_stat, 0, 1, __FILE__, __LINE__);

    ipp.ip.family = AF_INET6;
    DHT_assoc_candidate_new(dhtassoc, id, &ipp, seen);

    DHT_assoc_calc_statistics(dhtassoc, &assoc_stat);
    calls_maybe(&retvals, __LINE__);
    check_stat(&assoc_stat, 0, 1, __FILE__, __LINE__);
}
END_TEST

START_TEST(test_new_unwanted_seen)
{
    retvals_t retvals;
    DHT_assoc_callbacks callbacks;
    DHT_assoc *dhtassoc = init(&retvals, &callbacks);

    DHT_assoc_statistics assoc_stat;

    uint8_t id[CLIENT_ID_SIZE];
    id[1] = 1;

    IP_Port ipp;
    ipp.ip.ip4.uint8[0] = 200;
    ipp.ip.family = AF_INET;

    uint8_t seen = 1;

    DHT_assoc_candidate_new(dhtassoc, id, &ipp, seen);

    DHT_assoc_calc_statistics(dhtassoc, &assoc_stat);
    calls_maybe(&retvals, __LINE__);
    check_stat(&assoc_stat, 0, 1, __FILE__, __LINE__);

    ipp.ip.family = AF_INET6;
    DHT_assoc_candidate_new(dhtassoc, id, &ipp, seen);

    DHT_assoc_calc_statistics(dhtassoc, &assoc_stat);
    calls_maybe(&retvals, __LINE__);
    check_stat(&assoc_stat, 0, 1, __FILE__, __LINE__);

    ipp.ip.family = AF_INET;
    DHT_assoc_candidate_new(dhtassoc, id, &ipp, seen);

    DHT_assoc_calc_statistics(dhtassoc, &assoc_stat);
    calls_maybe(&retvals, __LINE__);
    check_stat(&assoc_stat, 0, 1, __FILE__, __LINE__);

    ipp.ip.family = AF_INET6;
    DHT_assoc_candidate_new(dhtassoc, id, &ipp, seen);

    DHT_assoc_calc_statistics(dhtassoc, &assoc_stat);
    calls_maybe(&retvals, __LINE__);
    check_stat(&assoc_stat, 0, 1, __FILE__, __LINE__);
}
END_TEST

START_TEST(test_new_wanted_seen_unused_drop)
{
    retvals_t retvals;
    DHT_assoc_callbacks callbacks;
    DHT_assoc *dhtassoc = init(&retvals, &callbacks);

    DHT_assoc_statistics assoc_stat;

    retvals.new.val = 1;

    uint8_t id[CLIENT_ID_SIZE];
    id[1] = 1;

    IP_Port ipp;
    ipp.ip.ip4.uint8[0] = 200;
    ipp.ip.family = AF_INET;

    uint8_t seen = 1;

    DHT_assoc_candidate_new(dhtassoc, id, &ipp, seen);

    DHT_assoc_calc_statistics(dhtassoc, &assoc_stat);
    calls_maybe(&retvals, __LINE__);
    check_stat(&assoc_stat, 1, 0, __FILE__, __LINE__);

    ck_assert_msg(retvals.usable.calls == 1, "Expected callback check_usable, didn't happen.");
    ck_assert_msg(retvals.usable.client_pos == 1, "Expected check_usable(..., 1, ...), got %u.",
                  retvals.usable.client_pos);

    DHT_assoc_client_drop(dhtassoc, retvals.usable.client_pos);

    DHT_assoc_calc_statistics(dhtassoc, &assoc_stat);
    calls_maybe(&retvals, __LINE__);
    check_stat(&assoc_stat, 0, 1, __FILE__, __LINE__);

    ck_assert_msg(retvals.delete.calls == 0, "Expected %u callbacks of check_delete, but got %u.",
                  0, retvals.delete.calls);
}
END_TEST

START_TEST(test_new_wanted_seen_unused_timeout)
{
    retvals_t retvals;
    DHT_assoc_callbacks callbacks;
    DHT_assoc *dhtassoc = init(&retvals, &callbacks);

    DHT_assoc_statistics assoc_stat;

    retvals.new.val = 1;

    uint8_t id[CLIENT_ID_SIZE];
    id[1] = 1;

    IP_Port ipp;
    ipp.ip.ip4.uint8[0] = 200;
    ipp.ip.family = AF_INET;

    uint8_t seen = 1;

    DHT_assoc_candidate_new(dhtassoc, id, &ipp, seen);

    DHT_assoc_calc_statistics(dhtassoc, &assoc_stat);
    calls_maybe(&retvals, __LINE__);
    check_stat(&assoc_stat, 1, 0, __FILE__, __LINE__);

    ck_assert_msg(retvals.usable.calls == 1, "Expected callback check_usable, didn't happen.");
    ck_assert_msg(retvals.usable.client_pos == 1, "Expected check_usable(..., 1, ...), got %u.",
                  retvals.usable.client_pos);

    /* should timeout anything */
    unix_time_force(10000);

    DHT_assoc_do(dhtassoc);

    DHT_assoc_calc_statistics(dhtassoc, &assoc_stat);
    calls_maybe(&retvals, __LINE__);
    check_stat(&assoc_stat, 0, 1, __FILE__, __LINE__);

    ck_assert_msg(retvals.delete.calls == 0, "Expected no callback check_delete, but it happened.");
}
END_TEST


START_TEST(test_new_wanted_seen_used_drop)
{
    retvals_t retvals;
    DHT_assoc_callbacks callbacks;
    DHT_assoc *dhtassoc = init(&retvals, &callbacks);

    DHT_assoc_statistics assoc_stat;

    retvals.new.val = 1;
    retvals.usable.val = 1;
    retvals.usage.val = 1;

    uint8_t id[CLIENT_ID_SIZE];
    id[1] = 1;

    IP_Port ipp;
    ipp.ip.ip4.uint8[0] = 200;
    ipp.ip.family = AF_INET;

    uint8_t seen = 1;

    DHT_assoc_candidate_new(dhtassoc, id, &ipp, seen);

    DHT_assoc_calc_statistics(dhtassoc, &assoc_stat);
    calls_maybe(&retvals, __LINE__);
    check_stat(&assoc_stat, 1, 0, __FILE__, __LINE__);

    ck_assert_msg(retvals.usable.calls == 1, "Expected callback check_usable, didn't happen.");
    ck_assert_msg(retvals.usable.client_pos == 1, "Expected check_usable(..., 1, ...), got %u.",
                  retvals.usable.client_pos);

    /* delete won't happen, because check_usage() returns 1 */
    DHT_assoc_client_drop(dhtassoc, retvals.usable.client_pos);

    DHT_assoc_calc_statistics(dhtassoc, &assoc_stat);
    calls_maybe(&retvals, __LINE__);
    check_stat(&assoc_stat, 1, 0, __FILE__, __LINE__);

    ck_assert_msg(retvals.delete.calls == 0, "Expected %u callbacks of check_delete, but got %u.",
                  0, retvals.delete.calls);

    /* don't block deletion any longer */
    retvals.usage.val = 0;

    DHT_assoc_client_drop(dhtassoc, retvals.usable.client_pos);

    DHT_assoc_calc_statistics(dhtassoc, &assoc_stat);
    calls_maybe(&retvals, __LINE__);
    check_stat(&assoc_stat, 0, 1, __FILE__, __LINE__);

    ck_assert_msg(retvals.delete.calls == 1, "Expected %u callbacks of check_delete, but got %u.",
                  1, retvals.delete.calls);
}
END_TEST

START_TEST(test_new_wanted_seen_used_timeout)
{
    retvals_t retvals;
    DHT_assoc_callbacks callbacks;
    DHT_assoc *dhtassoc = init(&retvals, &callbacks);

    DHT_assoc_statistics assoc_stat;

    retvals.new.val = 1;
    retvals.usable.val = 1;
    retvals.usage.val = 1;

    uint8_t id[CLIENT_ID_SIZE];
    id[1] = 1;

    IP_Port ipp;
    ipp.ip.ip4.uint8[0] = 200;
    ipp.ip.family = AF_INET;

    uint8_t seen = 1;

    DHT_assoc_candidate_new(dhtassoc, id, &ipp, seen);

    DHT_assoc_calc_statistics(dhtassoc, &assoc_stat);
    calls_maybe(&retvals, __LINE__);
    check_stat(&assoc_stat, 1, 0, __FILE__, __LINE__);

    ck_assert_msg(retvals.usable.calls == 1, "Expected callback check_usable, didn't happen.");
    ck_assert_msg(retvals.usable.client_pos == 1, "Expected check_usable(..., 1, ...), got %u.",
                  retvals.usable.client_pos);

    /* should timeout anything */
    unix_time_force(10000);

    DHT_assoc_do(dhtassoc);

    DHT_assoc_calc_statistics(dhtassoc, &assoc_stat);
    calls_maybe(&retvals, __LINE__);
    check_stat(&assoc_stat, 0, 1, __FILE__, __LINE__);

    ck_assert_msg(retvals.delete.calls == 1, "Expected %u callbacks of check_delete, but got %u.",
                  1, retvals.delete.calls);
}
END_TEST

START_TEST(test_close_nodes_find_unused)
{
    retvals_t retvals;
    DHT_assoc_callbacks callbacks;
    DHT_assoc *dhtassoc = init(&retvals, &callbacks);

    DHT_assoc_statistics assoc_stat;

    uint8_t id[CLIENT_ID_SIZE];
    id[1] = 1;

    IP_Port ipp;
    ipp.ip.ip4.uint8[0] = 200;
    ipp.ip.family = AF_INET;

    uint8_t i, seen = 0;

    for (i = 0; i < 255; i++) {
        DHT_assoc_candidate_new(dhtassoc, id, &ipp, seen);
        id[5]++;
        ipp.ip.ip4.uint8[3]++;
    }

    calls_maybe(&retvals, __LINE__);
    DHT_assoc_calc_statistics(dhtassoc, &assoc_stat);
    check_stat(&assoc_stat, 0, -128, __FILE__, __LINE__);

    seen = 1;
    id[0]++; /* different bucket ! */
    ipp.ip.ip4.uint8[2]++;

    for (i = 0; i < 255; i++) {
        DHT_assoc_candidate_new(dhtassoc, id, &ipp, seen);
        id[5]++;
        ipp.ip.ip4.uint8[3]++;
    }

    calls_maybe(&retvals, __LINE__);
    DHT_assoc_calc_statistics(dhtassoc, &assoc_stat);
    check_stat(&assoc_stat, 0, -256, __FILE__, __LINE__);

    uint8_t id_ref[CLIENT_ID_SIZE];

    DHT_assoc_close_nodes_simple state;
    memset(&state, 0, sizeof(state));
    state.close_count = 10;
    state.close_indices = calloc(10, sizeof(size_t));

    uint8_t found = DHT_assoc_close_nodes_find(dhtassoc, id_ref, &state);
    ck_assert_msg(found == 10, "Expected %u nodes, but got %u.",
                  10, found);

    calls_maybe(&retvals, __LINE__);
    DHT_assoc_calc_statistics(dhtassoc, &assoc_stat);
    check_stat(&assoc_stat, 10, -256, __FILE__, __LINE__);
}
END_TEST

START_TEST(test_close_nodes_find_used)
{
    retvals_t retvals;
    DHT_assoc_callbacks callbacks;
    DHT_assoc *dhtassoc = init(&retvals, &callbacks);

    DHT_assoc_statistics assoc_stat;

    retvals.new.val = 1;
    retvals.usable.val = 1;
    retvals.usage.val = 1;

    uint8_t id[CLIENT_ID_SIZE];
    id[1] = 1;

    IP_Port ipp;
    ipp.ip.ip4.uint8[0] = 200;
    ipp.ip.family = AF_INET;

    uint8_t i, seen = 0;

    for (i = 0; i < 255; i++) {
        DHT_assoc_candidate_new(dhtassoc, id, &ipp, seen);
        id[5]++;
        ipp.ip.ip4.uint8[3]++;
    }

    calls_maybe(&retvals, __LINE__);
    DHT_assoc_calc_statistics(dhtassoc, &assoc_stat);
    check_stat(&assoc_stat, 0, -128, __FILE__, __LINE__);

    seen = 1;
    id[4]++;
    ipp.ip.ip4.uint8[2]++;

    for (i = 0; i < 255; i++) {
        DHT_assoc_candidate_new(dhtassoc, id, &ipp, seen);
        id[5]++;
        ipp.ip.ip4.uint8[3]++;
    }

    calls_maybe(&retvals, __LINE__);
    DHT_assoc_calc_statistics(dhtassoc, &assoc_stat);
    check_stat(&assoc_stat, 255, -128, __FILE__, __LINE__);

    uint8_t id_ref[CLIENT_ID_SIZE];

    DHT_assoc_close_nodes_simple state;
    memset(&state, 0, sizeof(state));
    state.close_count = 10;
    state.close_indices = calloc(10, sizeof(size_t));

    uint8_t found = DHT_assoc_close_nodes_find(dhtassoc, id_ref, &state);
    ck_assert_msg(found == 10, "Expected %u nodes, but got %u.",
                  10, found);

    calls_maybe(&retvals, __LINE__);
    DHT_assoc_calc_statistics(dhtassoc, &assoc_stat);
    check_stat(&assoc_stat, 255, -128, __FILE__, __LINE__);
}
END_TEST

START_TEST(test_search_helper)
{
    uint16_t hash = 1024;
    uint16_t hashes[1024];
    size_t i, k, m, o, q, s;
    uint16_t first, last, testmax = 16;

    for (i = 0; i < testmax; i++) {
        for (o = 0; o < i; o++)
            hashes[o] = o + 1;

        for (k = 0; k < testmax; k++) {
            for (q = 0; q < k; q++)
                hashes[i + q] = hash;

            for (m = 0; m < testmax; m++) {

                for (s = 0; s < m; s++)
                    hashes[i + k + s] = hash + 1 + s;

                // fprintf(stderr, "testing: search_helper with %u %u %u\n", i, k, m);
                uint8_t res = DHT_assoc_testing_search_helper(hash, hashes, i + k + m, &first, &last);

                if (k > 0) {
                    ck_assert_msg(res != 0, "search_helper[%u, %u, %u]: Expected result \"success\", got \"failure\".",
                                  i, k, m);
                    ck_assert_msg(first == i, "search_helper[%u, %u, %u]: Expected first of %u, got %u.",
                                  i, k, m, i, first);
                    ck_assert_msg(last == i + k - 1, "search_helper[%u, %u, %u]: Expected last of %u, got %u.",
                                  i, k, m, i + k - 1, last);
                } else {
                    ck_assert_msg(res == 0, "Expected result \"failure\", got \"success\": i, k, m: %u, %u, %u, first, last: %u, %u.",
                                  i, k, m, first, last);
                }
            }
        }
    }
}
END_TEST



#define DEFTESTCASE(NAME) \
    TCase *tc_##NAME = tcase_create(#NAME); \
    tcase_add_test(tc_##NAME, test_##NAME); \
    suite_add_tcase(s, tc_##NAME);

#define DEFTESTCASE_SLOW(NAME, TIMEOUT) \
    DEFTESTCASE(NAME) \
    tcase_set_timeout(tc_##NAME, TIMEOUT);

Suite *DHT_assoc_suite(void)
{
    Suite *s = suite_create("DHT_assoc");

    DEFTESTCASE(new_unwanted_unseen);
    DEFTESTCASE(new_unwanted_seen);
    DEFTESTCASE(new_wanted_unseen);

    DEFTESTCASE(new_wanted_seen_unused_drop);
    DEFTESTCASE(new_wanted_seen_unused_timeout);
    DEFTESTCASE(new_wanted_seen_used_drop);
    DEFTESTCASE(new_wanted_seen_used_timeout);

    DEFTESTCASE(close_nodes_find_unused);
    DEFTESTCASE(close_nodes_find_used);

    DEFTESTCASE_SLOW(search_helper, 30); /* waiting up to 30 seconds */

    return s;
}

int main(int argc, char *argv[])
{
    Suite *DHT_assoc = DHT_assoc_suite();
    SRunner *test_runner = srunner_create(DHT_assoc);

    srunner_set_fork_status(test_runner, CK_NOFORK);

    srunner_run_all(test_runner, CK_NORMAL);

    int number_failed = srunner_ntests_failed(test_runner);

    srunner_free(test_runner);

    return number_failed;
}
