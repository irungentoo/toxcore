// This test checks that we can create two conferences and quit properly.
//
// This test triggers a different code path than if we only allocate a single
// conference. This is the simplest test possible that triggers it.

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "../testing/misc_tools.h"
#include "../toxcore/tox.h"
#include "check_compat.h"

int main(void)
{
    // Create toxes.
    uint32_t id = 1;
    Tox *tox1 = tox_new_log(nullptr, nullptr, &id);

    // Create two conferences and then exit.
    TOX_ERR_CONFERENCE_NEW err;
    tox_conference_new(tox1, &err);
    ck_assert_msg(err == TOX_ERR_CONFERENCE_NEW_OK, "failed to create conference 1: %d", err);
    tox_conference_new(tox1, &err);
    ck_assert_msg(err == TOX_ERR_CONFERENCE_NEW_OK, "failed to create conference 2: %d", err);

    tox_kill(tox1);

    return 0;
}
