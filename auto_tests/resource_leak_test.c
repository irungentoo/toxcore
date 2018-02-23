#if defined(__AIX__)
#define _XOPEN_SOURCE 1
#endif

#include "helpers.h"

// See man 2 sbrk.
#if defined(_BSD_SOURCE) || defined(_SVID_SOURCE) || \
  defined(_XOPEN_SOURCE) && (_XOPEN_SOURCE >= 500 || defined(_XOPEN_SOURCE_EXTENDED)) && \
  !(defined(_POSIX_C_SOURCE) && _POSIX_C_SOURCE >= 200112L || _XOPEN_SOURCE >= 600)
#define HAVE_SBRK 1
#else
#define HAVE_SBRK 0
#endif

#if HAVE_SBRK
#include <assert.h>
#include <unistd.h>
#endif

#define ITERATIONS 20000

int main(void)
{
    setvbuf(stdout, nullptr, _IONBF, 0);

    puts("Warming up: creating/deleting 10 tox instances");

    // Warm-up.
    for (int i = 0; i < 10; i++) {
        Tox *tox = tox_new(nullptr, nullptr);
        tox_iterate(tox, nullptr);
        tox_kill(tox);
    }

#if HAVE_SBRK
    // Low water mark.
    char *hwm = (char *)sbrk(0);
#endif
    printf("Creating/deleting %d tox instances\n", ITERATIONS);

    int allocated = 0;

    for (int i = 0; i < ITERATIONS; i++) {
        Tox *tox = tox_new(nullptr, nullptr);

        if (tox != nullptr) {
            tox_iterate(tox, nullptr);
            tox_kill(tox);
            allocated++;
        }

#if HAVE_SBRK
        char *next_hwm = (char *)sbrk(0);
        assert(hwm == next_hwm);
#endif
    }

    assert(allocated >= ITERATIONS / 2);
    printf("Success: no resource leaks detected in %d tox_new calls (tried %d)\n",
           allocated, ITERATIONS);

    return 0;
}
