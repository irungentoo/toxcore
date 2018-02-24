#include "../toxcore/tox.h"

#include <stdio.h>
#include <stdlib.h>

#define check(major, minor, patch, expected)                            \
  do_check(TOX_VERSION_MAJOR, TOX_VERSION_MINOR, TOX_VERSION_PATCH,     \
           major, minor, patch,                                         \
           TOX_VERSION_IS_API_COMPATIBLE(major, minor, patch), expected,\
           &result)

static void do_check(int lib_major, int lib_minor, int lib_patch,
                     int cli_major, int cli_minor, int cli_patch,
                     bool actual, bool expected,
                     int *result)
{
    if (actual != expected) {
        printf("Client version %d.%d.%d is%s compatible with library version %d.%d.%d, but it should%s be\n",
               cli_major, cli_minor, cli_patch, actual ? "" : " not",
               lib_major, lib_minor, lib_patch, expected ? "" : " not");
        *result = EXIT_FAILURE;
    }
}

#undef TOX_VERSION_MAJOR
#undef TOX_VERSION_MINOR
#undef TOX_VERSION_PATCH

int main(void)
{
    int result = 0;
#define TOX_VERSION_MAJOR 0
#define TOX_VERSION_MINOR 0
#define TOX_VERSION_PATCH 4
    check(0, 0, 0, false);
    check(0, 0, 4, true);
    check(0, 0, 5, false);
    check(1, 0, 4, false);
#undef TOX_VERSION_MAJOR
#undef TOX_VERSION_MINOR
#undef TOX_VERSION_PATCH

#define TOX_VERSION_MAJOR 0
#define TOX_VERSION_MINOR 1
#define TOX_VERSION_PATCH 4
    check(0, 0, 0, false);
    check(0, 0, 4, false);
    check(0, 0, 5, false);
    check(0, 1, 0, true);
    check(0, 1, 4, true);
    check(0, 1, 5, false);
    check(0, 2, 0, false);
    check(0, 2, 4, false);
    check(0, 2, 5, false);
    check(1, 0, 0, false);
    check(1, 0, 4, false);
    check(1, 0, 5, false);
#undef TOX_VERSION_MAJOR
#undef TOX_VERSION_MINOR
#undef TOX_VERSION_PATCH

#define TOX_VERSION_MAJOR 1
#define TOX_VERSION_MINOR 0
#define TOX_VERSION_PATCH 4
    check(1, 0, 0, true);
    check(1, 0, 1, true);
    check(1, 0, 4, true);
    check(1, 0, 5, false);
    check(1, 1, 0, false);
#undef TOX_VERSION_MAJOR
#undef TOX_VERSION_MINOR
#undef TOX_VERSION_PATCH

#define TOX_VERSION_MAJOR 1
#define TOX_VERSION_MINOR 1
#define TOX_VERSION_PATCH 4
    check(1, 0, 0, true);
    check(1, 0, 4, true);
    check(1, 0, 5, true);
    check(1, 1, 0, true);
    check(1, 1, 1, true);
    check(1, 1, 4, true);
    check(1, 1, 5, false);
    check(1, 2, 0, false);
    check(1, 2, 4, false);
    check(1, 2, 5, false);
    check(2, 0, 0, false);
#undef TOX_VERSION_MAJOR
#undef TOX_VERSION_MINOR
#undef TOX_VERSION_PATCH

    return result;
}
