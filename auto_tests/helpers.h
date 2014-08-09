#ifndef TOXCORE_TEST_HELPERS_H
#define TOXCORE_TEST_HELPERS_H

#include <check.h>

#define DEFTESTCASE(NAME)                   \
    TCase *tc_##NAME = tcase_create(#NAME); \
    tcase_add_test(tc_##NAME, test_##NAME); \
    suite_add_tcase(s, tc_##NAME);

#define DEFTESTCASE_SLOW(NAME, TIMEOUT) \
    DEFTESTCASE(NAME) \
    tcase_set_timeout(tc_##NAME, TIMEOUT);

#endif // TOXCORE_TEST_HELPERS_H
