#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <check.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <time.h>

#include "helpers.h"

#include "../testing/misc_tools.c"

typedef enum {
    NEGATIVE,
    ZERO,
    POSITIVE
} Comparison;

static const char *Comparison_Str[] = { "NEGATIVE", "ZERO", "POSITIVE" };

void verify(const char *s1, const char *s2, size_t n, Comparison expected)
{
    int r = tox_strncasecmp(s1, s2, n);
    Comparison actual = r < 0 ? NEGATIVE : r == 0 ? ZERO : POSITIVE;

    ck_assert_msg(actual == expected,
                  "tox_strncasecmp(\"%s\", \"%s\", %u) == %s, but expected %s.",
                  s1, s2, n, Comparison_Str[actual], Comparison_Str[expected]);
}

START_TEST(test_general)
{
    // empty strings are equal
    verify("", "", 100, ZERO);
    verify("", "", -1, ZERO);

    // ====== Same Case Test Cases ======

    // equal strings with n=0 are equal
    verify("", "", 0, ZERO);
    verify("AAA", "AAA", 0, ZERO);

    // unequal strings with n=0 are equal
    verify("A", "B", 0, ZERO);
    verify("AAA", "BBB", 0, ZERO);
    verify("AAA", "BBBBBB", 0 , ZERO);
    verify("AAAAAA", "BBB", 0, ZERO);

    // equal strings are equal
    verify("AAA", "AAA", 0, ZERO);
    verify("AAA", "AAA", 1, ZERO);
    verify("AAA", "AAA", 2, ZERO);
    verify("AAA", "AAA", 3, ZERO);
    verify("AAA", "AAA", 4, ZERO);
    verify("AAA", "AAA", 5, ZERO);
    verify("AAA", "AAA", -1, ZERO);

    verify("AAA", "AAAAAA", 0, ZERO);
    verify("AAA", "AAAAAA", 1, ZERO);
    verify("AAA", "AAAAAA", 2, ZERO);
    verify("AAA", "AAAAAA", 3, ZERO);
    verify("AAA", "AAAAAA", 4, NEGATIVE);
    verify("AAA", "AAAAAA", 5, NEGATIVE);
    verify("AAA", "AAAAAA", -1, NEGATIVE);

    verify("AAAAAA", "AAA", 0, ZERO);
    verify("AAAAAA", "AAA", 1, ZERO);
    verify("AAAAAA", "AAA", 2, ZERO);
    verify("AAAAAA", "AAA", 3, ZERO);
    verify("AAAAAA", "AAA", 4, POSITIVE);
    verify("AAAAAA", "AAA", 5, POSITIVE);
    verify("AAAAAA", "AAA", -1, POSITIVE);

    verify("I'm eating wafers and drinking tea.", "I'm eating wafers and drinking tea.", -1, ZERO);

    // unequal strings are equal only up to n
    verify("AAAB", "AAAA", 0, ZERO);
    verify("AAAB", "AAAA", 1, ZERO);
    verify("AAAB", "AAAA", 2, ZERO);
    verify("AAAB", "AAAA", 3, ZERO);
    verify("AAAB", "AAAA", 4, POSITIVE);
    verify("AAAB", "AAAA", 5, POSITIVE);
    verify("AAAB", "AAAA", -1, POSITIVE);

    verify("AAAA", "AAAB", 0, ZERO);
    verify("AAAA", "AAAB", 1, ZERO);
    verify("AAAA", "AAAB", 2, ZERO);
    verify("AAAA", "AAAB", 3, ZERO);
    verify("AAAA", "AAAB", 4, NEGATIVE);
    verify("AAAA", "AAAB", 5, NEGATIVE);
    verify("AAAA", "AAAB", -1, NEGATIVE);

    verify("The wafers are salty.", "The wafers are sweet.", 16, ZERO);
    verify("The wafers are salty.", "The wafers are sweet.", 17, NEGATIVE);
    verify("The wafers are salty.", "The wafers are sweet.", -1, NEGATIVE);

    // the comparison should stop at first mismatch
    verify("AAABA", "AAAAB", -1, POSITIVE);
    verify("AAAAB", "AAABA", -1, NEGATIVE);

    // ====== Different Case Test Cases ======

    // equal strings with n=0 are equal
    verify("", "", 0, ZERO);
    verify("aaa", "AAA", 0, ZERO);

    // unequal strings with n=0 are equal
    verify("a", "B", 0, ZERO);
    verify("aaa", "BBB", 0, ZERO);
    verify("aaa", "BBBBBB", 0 , ZERO);
    verify("aaaaaa", "BBB", 0, ZERO);

    // equal strings are equal
    verify("aaa", "AAA", 0, ZERO);
    verify("AAA", "aaa", 1, ZERO);
    verify("aaa", "AAA", 2, ZERO);
    verify("aaa", "AAA", 3, ZERO);
    verify("AAA", "aaa", 4, ZERO);
    verify("AAA", "aaa", 5, ZERO);
    verify("AAA", "aaa", -1, ZERO);

    verify("aaa", "AAAAAA", 0, ZERO);
    verify("AAA", "AAAaaa", 1, ZERO);
    verify("aaA", "aaaAAA", 2, ZERO);
    verify("AaA", "aAAAAA", 3, ZERO);
    verify("AAA", "AAAAAA", 4, NEGATIVE);
    verify("Aaa", "AAaaAA", 5, NEGATIVE);
    verify("AAA", "AAAAAa", -1, NEGATIVE);

    verify("AAAAAA", "aaa", 0, ZERO);
    verify("AAAaaa", "AAA", 1, ZERO);
    verify("aaaAAA", "aaA", 2, ZERO);
    verify("aAAAAA", "AaA", 3, ZERO);
    verify("AAAAAA", "AAA", 4, POSITIVE);
    verify("AAaaAA", "Aaa", 5, POSITIVE);
    verify("AAAAAa", "AAA", -1, POSITIVE);

    verify("I'm Eating Wafers And Drinking Tea.", "I'm eating wafers and drinking tea.", -1, ZERO);

    // unequal strings are equal only up to n
    verify("aaaB", "AAAA", 0, ZERO);
    verify("AaAB", "aAAA", 1, ZERO);
    verify("aAAB", "AaAA", 2, ZERO);
    verify("AAAB", "AAaA", 3, ZERO);
    verify("AAAB", "AAAA", 4, POSITIVE);
    verify("AAAb", "AAAA", 5, POSITIVE);
    verify("AAAB", "AAAa", -1, POSITIVE);

    verify("AAAA", "aaaB", 0, ZERO);
    verify("aAAA", "AaAB", 1, ZERO);
    verify("AaAA", "aAAB", 2, ZERO);
    verify("AAaA", "AAAB", 3, ZERO);
    verify("AAAA", "AAAB", 4, NEGATIVE);
    verify("AAAA", "AAAb", 5, NEGATIVE);
    verify("AAAa", "AAAB", -1, NEGATIVE);

    verify("The Wafers Are Salty.", "The wafers are sweet.", 16, ZERO);
    verify("The Wafers Are Salty.", "The wafers are sweet.", 17, NEGATIVE);
    verify("The Wafers Are Salty.", "The wafers are sweet.", -1, NEGATIVE);

    // the comparison should stop at first mismatch
    verify("aAaBA", "AAAAb", -1, POSITIVE);
    verify("AAAAb", "aAaBA", -1, NEGATIVE);
}
END_TEST

static Suite *tox_strncasecmp_suite(void)
{
    Suite *s = suite_create("tox_strncasecmp");

    DEFTESTCASE(general);

    return s;
}

int main(int argc, char *argv[])
{
    srand((unsigned int) time(NULL));

    Suite *s = tox_strncasecmp_suite();
    SRunner *test_runner = srunner_create(s);

    int number_failed = 0;
    srunner_run_all(test_runner, CK_NORMAL);
    number_failed = srunner_ntests_failed(test_runner);

    srunner_free(test_runner);

    return number_failed;
}
