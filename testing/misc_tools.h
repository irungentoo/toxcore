#ifndef C_TOXCORE_TESTING_MISC_TOOLS_H
#define C_TOXCORE_TESTING_MISC_TOOLS_H

#include "../toxcore/tox.h"

#ifdef __cplusplus
extern "C" {
#endif

// Amount of time in milliseconds to wait between tox_iterate calls.
#define ITERATION_INTERVAL 200

void c_sleep(uint32_t x);

uint8_t *hex_string_to_bin(const char *hex_string);
int tox_strncasecmp(const char *s1, const char *s2, size_t n);
int cmdline_parsefor_ipv46(int argc, char **argv, uint8_t *ipv6enabled);

void print_debug_log(Tox *m, TOX_LOG_LEVEL level, const char *file, uint32_t line, const char *func,
                     const char *message, void *user_data);

Tox *tox_new_log(struct Tox_Options *options, TOX_ERR_NEW *err, void *log_user_data);
Tox *tox_new_log_lan(struct Tox_Options *options, TOX_ERR_NEW *err, void *log_user_data, bool lan_discovery);

int use_test_rng(uint32_t seed);

#ifdef __cplusplus
}
#endif

#endif
