#ifndef C_TOXCORE_TESTING_MISC_TOOLS_H
#define C_TOXCORE_TESTING_MISC_TOOLS_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

// Amount of time in milliseconds to wait between tox_iterate calls.
#define ITERATION_INTERVAL 200

void c_sleep(uint32_t x);

uint8_t *hex_string_to_bin(const char *hex_string);
void to_hex(char *out, uint8_t *in, int size);
int tox_strncasecmp(const char *s1, const char *s2, size_t n);
int cmdline_parsefor_ipv46(int argc, char **argv, bool *ipv6enabled);

int use_test_rng(uint32_t seed);

#ifdef __cplusplus
} /* extern "C" */
#endif

#endif
