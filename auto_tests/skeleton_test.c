#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <sys/types.h>
#include <stdint.h>
#include <string.h>
#include <check.h>
#include <stdlib.h>
#include <time.h>

/*
#include "../<stuff to test>"
*/

START_TEST(test_creativetestnamegoeshere)
{
    uint8_t test = 0;
    ck_assert_msg(test == 0, "test: expected result 0, got %u.", test);
}
END_TEST


#define DEFTESTCASE(NAME) \
    TCase *tc_##NAME = tcase_create(#NAME); \
    tcase_add_test(tc_##NAME, test_##NAME); \
    suite_add_tcase(s, tc_##NAME);

Suite *creativesuitenamegoeshere_suite(void)
{
    Suite *s = suite_create("creativesuitedescritptiongoeshere");

    DEFTESTCASE(/* remove test_ from test function names */ creativetestnamegoeshere);

    return s;
}

int main(int argc, char *argv[])
{
    srand((unsigned int) time(NULL));

    Suite *creativesuitenamegoeshere = creativesuitenamegoeshere_suite();
    SRunner *test_runner = srunner_create(creativesuitenamegoeshere);

    int number_failed = 0;
    srunner_run_all(test_runner, CK_NORMAL);
    number_failed = srunner_ntests_failed(test_runner);

    srunner_free(test_runner);

    return number_failed;
}

