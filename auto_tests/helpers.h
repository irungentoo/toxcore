#ifndef TOXCORE_TEST_HELPERS_H
#define TOXCORE_TEST_HELPERS_H

#include "../toxcore/tox.h"

#include <check.h>
#include <stdio.h>

#define DEFTESTCASE(NAME)                   \
    TCase *tc_##NAME = tcase_create(#NAME); \
    tcase_add_test(tc_##NAME, test_##NAME); \
    suite_add_tcase(s, tc_##NAME);

#define DEFTESTCASE_SLOW(NAME, TIMEOUT) \
    DEFTESTCASE(NAME) \
    tcase_set_timeout(tc_##NAME, TIMEOUT);

static const char *tox_log_level_name(TOX_LOG_LEVEL level)
{
    switch (level) {
        case TOX_LOG_LEVEL_TRACE:
            return "TRACE";

        case TOX_LOG_LEVEL_DEBUG:
            return "DEBUG";

        case TOX_LOG_LEVEL_INFO:
            return "INFO";

        case TOX_LOG_LEVEL_WARNING:
            return "WARNING";

        case TOX_LOG_LEVEL_ERROR:
            return "ERROR";
    }
}

static void print_debug_log(Tox *m, TOX_LOG_LEVEL level, const char *path, uint32_t line, const char *func,
                            const char *message, void *user_data)
{
    if (level == TOX_LOG_LEVEL_TRACE) {
        return;
    }

    uint32_t index = user_data ? *(uint32_t *)user_data : 0;
    const char *file = strrchr(path, '/');
    file = file ? file + 1 : path;
    printf("[#%d] %s %s:%d\t%s:\t%s\n", index, tox_log_level_name(level), file, line, func, message);
}

Tox *tox_new_log(struct Tox_Options *options, TOX_ERR_NEW *err, void *log_user_data)
{
    struct Tox_Options *my_options = tox_options_new(NULL);

    if (options != NULL) {
        *my_options = *options;
    }

    tox_options_set_log_callback(my_options, &print_debug_log);
    tox_options_set_log_user_data(my_options, log_user_data);
    Tox *tox = tox_new(my_options, err);
    tox_options_free(my_options);
    return tox;
}

#endif // TOXCORE_TEST_HELPERS_H
