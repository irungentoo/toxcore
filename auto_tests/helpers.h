#ifndef TOXCORE_TEST_HELPERS_H
#define TOXCORE_TEST_HELPERS_H

#include "../toxcore/tox.h"

#include "../toxcore/ccompat.h"

#include <assert.h>
#include <stdio.h>
#include <string.h>

#if defined(_WIN32) || defined(__WIN32__) || defined(WIN32)
#include <windows.h>
#define c_sleep(x) Sleep(x)
#else
#include <unistd.h>
#define c_sleep(x) usleep(1000 * (x))
#endif

#define ITERATION_INTERVAL 200

Tox *tox_new_log(struct Tox_Options *options, TOX_ERR_NEW *err, void *log_user_data);

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

    return "<unknown>";
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
    fprintf(stderr, "[#%d] %s %s:%d\t%s:\t%s\n", index, tox_log_level_name(level), file, line, func, message);
}

static Tox *tox_new_log_lan(struct Tox_Options *options, TOX_ERR_NEW *err, void *log_user_data, bool lan_discovery)
{
    struct Tox_Options *log_options = options;

    if (log_options == nullptr) {
        log_options = tox_options_new(nullptr);
    }

    assert(log_options != nullptr);

    tox_options_set_local_discovery_enabled(log_options, lan_discovery);
    tox_options_set_start_port(log_options, 33445);
    tox_options_set_end_port(log_options, 33445 + 2000);
    tox_options_set_log_callback(log_options, &print_debug_log);
    tox_options_set_log_user_data(log_options, log_user_data);
    Tox *tox = tox_new(log_options, err);

    if (options == nullptr) {
        tox_options_free(log_options);
    }

    return tox;
}

Tox *tox_new_log(struct Tox_Options *options, TOX_ERR_NEW *err, void *log_user_data)
{
    return tox_new_log_lan(options, err, log_user_data, false);
}

#endif // TOXCORE_TEST_HELPERS_H
