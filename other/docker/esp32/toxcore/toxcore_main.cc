#include <stdio.h>

#include "../../../../toxcore/ccompat.h"
#include "../../../../toxcore/tox.h"
#include "../../../../toxcore/tox_events.h"

extern "C" void app_main(void)
{
    printf("Hello Tox!\n");

    Tox *tox = tox_new(nullptr, nullptr);
    tox_events_free(tox_events_iterate(tox, true, nullptr));
    tox_kill(tox);
}
