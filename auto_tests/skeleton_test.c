#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <stdlib.h>

#include "../testing/misc_tools.h"
#include "check_compat.h"

/*
#include "../<stuff to test>"
*/

START_TEST(test_creativetestnamegoeshere)
{
    uint8_t test = 0;
    ck_assert_msg(test == 0, "test: expected result 0, got %u.", test);
}
END_TEST

static Suite *creativesuitenamegoeshere_suite(void)
{
    Suite *s = suite_create("creativesuitedescritptiongoeshere");

    DEFTESTCASE(/* remove test_ from test function names */ creativetestnamegoeshere);

    return s;
}

int main(void)
{
    setvbuf(stdout, nullptr, _IONBF, 0);

    Suite *creativesuitenamegoeshere = creativesuitenamegoeshere_suite();
    SRunner *test_runner = srunner_create(creativesuitenamegoeshere);

    int number_failed = 0;
    srunner_run_all(test_runner, CK_NORMAL);
    number_failed = srunner_ntests_failed(test_runner);

    srunner_free(test_runner);

    return number_failed;
}
