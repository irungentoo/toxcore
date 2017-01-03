#include "helpers.h"

#if defined(__AIX__)
#   define _XOPEN_SOURCE 1
#endif

// See man 2 sbrk.
#if _BSD_SOURCE || _SVID_SOURCE || \
  (_XOPEN_SOURCE >= 500 || \
   _XOPEN_SOURCE && _XOPEN_SOURCE_EXTENDED) && \
  !(_POSIX_C_SOURCE >= 200112L || _XOPEN_SOURCE >= 600)
#define HAVE_SBRK 1
#endif

#if HAVE_SBRK
#include <assert.h>
#include <unistd.h>
#endif

#define ITERATIONS 20000

int main(void)
{
    int i;

    puts("Warming up: creating/deleting 10 tox instances");

    // Warm-up.
    for (i = 0; i < 10; i++) {
        Tox *tox = tox_new(0, 0);
        tox_iterate(tox, NULL);
        tox_kill(tox);
    }

#if HAVE_SBRK
    // Low water mark.
    char *hwm = (char *)sbrk(0);
#endif
    printf("Creating/deleting %d tox instances\n", ITERATIONS);

    for (i = 0; i < ITERATIONS; i++) {
        Tox *tox = tox_new(0, 0);
        tox_iterate(tox, NULL);
        tox_kill(tox);
#if HAVE_SBRK
        char *next_hwm = (char *)sbrk(0);
        assert(hwm == next_hwm);
#endif
    }

    puts("Success: no resource leaks detected");

    return 0;
}
