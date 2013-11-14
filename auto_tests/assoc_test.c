
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

START_TEST(test_X)
{
    /* TODO: real test */
    Assoc *assoc = new_Assoc(NULL);

    uint8_t id[CLIENT_ID_SIZE];
    IPPTs ippts_send;
    IP_Port ipp_recv;

    Assoc_add_entry(assoc, id, &ippts_send, &ipp_recv);

    Assoc_close_entries close_entries;
    memset(&close_entries, 0, sizeof(close_entries));

    /* uint8_t found = */ Assoc_get_close_entries(assoc, &close_entries);
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

    DEFTESTCASE(X);

    return s;
}

int main(int argc, char *argv[])
{
    Suite *Assoc = Assoc_suite();
    SRunner *test_runner = srunner_create(Assoc);

    srunner_set_fork_status(test_runner, CK_NOFORK);

    srunner_run_all(test_runner, CK_NORMAL);

    int number_failed = srunner_ntests_failed(test_runner);

    srunner_free(test_runner);

    return number_failed;
}
