#ifndef CHECK_COMPAT_H
#define CHECK_COMPAT_H

#include "../toxcore/ccompat.h"

#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>

#define START_TEST(name) static void name(void)
#define END_TEST

#define DEFTESTCASE(NAME) test_##NAME()
#define DEFTESTCASE_SLOW(NAME, TIMEOUT) test_##NAME()

typedef struct Suite Suite;
typedef struct SRunner SRunner;
enum SRunMode { CK_NORMAL };

static inline Suite *suite_create(const char *title)
{
    printf("Running test suite: %s\n", title);
    return nullptr;
}

static inline SRunner *srunner_create(Suite *s)
{
    return nullptr;
}

static inline void srunner_free(SRunner *s)
{
}

static inline void srunner_run_all(SRunner *r, int mode)
{
}

static inline int srunner_ntests_failed(SRunner *r)
{
    return 0;
}

#define ck_assert(ok) do {                                              \
  if (!(ok)) {                                                          \
    fprintf(stderr, "%s:%d: failed `%s'\n", __FILE__, __LINE__, #ok);   \
    abort();                                                            \
  }                                                                     \
} while (0)

#define ck_assert_msg(ok, ...) do {                                     \
  if (!(ok)) {                                                          \
    fprintf(stderr, "%s:%d: failed `%s': ", __FILE__, __LINE__, #ok);   \
    fprintf(stderr, __VA_ARGS__);                                       \
    fprintf(stderr, "\n");                                              \
    abort();                                                            \
  }                                                                     \
} while (0)

#define ck_abort_msg(...) do {                                          \
  fprintf(stderr, "%s:%d: ", __FILE__, __LINE__);                       \
  fprintf(stderr, __VA_ARGS__);                                         \
  fprintf(stderr, "\n");                                                \
  abort();                                                              \
} while (0)

#endif // CHECK_COMPAT_H
