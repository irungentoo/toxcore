#ifndef C_TOXCORE_AUTO_TESTS_CHECK_COMPAT_H
#define C_TOXCORE_AUTO_TESTS_CHECK_COMPAT_H

#include "../toxcore/ccompat.h"

#include <stdio.h>
#include <stdlib.h>

#ifndef ck_assert
#define ck_assert(ok)                                                         \
    do {                                                                      \
        if (!(ok)) {                                                          \
            fprintf(stderr, "%s:%d: failed `%s'\n", __FILE__, __LINE__, #ok); \
            exit(7);                                                          \
        }                                                                     \
    } while (0)

#define ck_assert_msg(ok, ...)                                                \
    do {                                                                      \
        if (!(ok)) {                                                          \
            fprintf(stderr, "%s:%d: failed `%s': ", __FILE__, __LINE__, #ok); \
            fprintf(stderr, __VA_ARGS__);                                     \
            fprintf(stderr, "\n");                                            \
            exit(7);                                                          \
        }                                                                     \
    } while (0)

#define ck_assert_int_eq(a, b)                                                                   \
    do {                                                                                         \
        const int32_t _a = (a);                                                                  \
        const int32_t _b = (b);                                                                  \
        if (_a != _b) {                                                                          \
            fprintf(stderr, "%s:%d: failed `%s == %s` (%d != %d)\n", __FILE__, __LINE__, #a, #b, \
                _a, _b);                                                                         \
            exit(7);                                                                             \
        }                                                                                        \
    } while (0)

#define ck_assert_uint_eq(a, b)                                                                  \
    do {                                                                                         \
        const uint32_t _a = (a);                                                                 \
        const uint32_t _b = (b);                                                                 \
        if (_a != _b) {                                                                          \
            fprintf(stderr, "%s:%d: failed `%s == %s` (%u != %u)\n", __FILE__, __LINE__, #a, #b, \
                _a, _b);                                                                         \
            exit(7);                                                                             \
        }                                                                                        \
    } while (0)

#define ck_abort_msg(...)                               \
    do {                                                \
        fprintf(stderr, "%s:%d: ", __FILE__, __LINE__); \
        fprintf(stderr, __VA_ARGS__);                   \
        fprintf(stderr, "\n");                          \
        exit(7);                                        \
    } while (0)
#endif

#endif // C_TOXCORE_AUTO_TESTS_CHECK_COMPAT_H
