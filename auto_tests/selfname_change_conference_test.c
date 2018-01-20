/* selfname_change_conference_test.c
 *
 * Small test for checking if obtaining savedata, saving it to disk and using
 * works correctly.
 *
 *  Copyright (C) 2017 Tox project All Rights Reserved.
 *
 *  This file is part of Tox.
 *
 *  Tox is free software: you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation, either version 3 of the License, or
 *  (at your option) any later version.
 *
 *  Tox is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with Tox.  If not, see <http://www.gnu.org/licenses/>.
 *
 */
#define _XOPEN_SOURCE 500

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include "helpers.h"

#include "../toxcore/tox.h"
#include "../toxencryptsave/toxencryptsave.h"

static const char *newname = "chris";

static void cbconfmembers(Tox *tox, uint32_t conference_number, uint32_t peer_number,
                          TOX_CONFERENCE_STATE_CHANGE change,
                          void *user_data)
{
    uint8_t new_peer_name[TOX_MAX_NAME_LENGTH + 1];

    if (change != TOX_CONFERENCE_STATE_CHANGE_PEER_NAME_CHANGE) {
        return;
    }

    if (!tox_conference_peer_get_name(tox, conference_number, peer_number, new_peer_name, NULL)) {
        return;
    }

    if (!memcmp(newname, new_peer_name, tox_conference_peer_get_name_size(tox, conference_number, peer_number, NULL))) {
        printf("success: own name was changed and updated in the conference");
        exit(0);
    }
}

int main(void)
{
    struct Tox_Options *to = tox_options_new(NULL);
    Tox *t;
    TOX_ERR_CONFERENCE_NEW conference_err;
    TOX_ERR_SET_INFO name_err;

    t = tox_new(to, NULL);
    tox_options_free(to);

    tox_callback_conference_namelist_change(t, cbconfmembers);

    if (tox_conference_new(t, &conference_err) == UINT32_MAX) {
        tox_kill(t);
        fprintf(stderr, "error: could not create new conference, error code %d\n", conference_err);
        return 2;
    }

    tox_iterate(t, NULL);
    c_sleep(tox_iteration_interval(t));

    if (!tox_self_set_name(t, (const uint8_t *)newname, strlen(newname), &name_err)) {
        tox_kill(t);
        fprintf(stderr, "error: could not set own name, error code %d\n", name_err);
        return 3;
    }

    tox_iterate(t, NULL);
    c_sleep(tox_iteration_interval(t));
    tox_iterate(t, NULL);

    fprintf(stderr, "error: name was not changed in callback. exiting.\n");

    tox_kill(t);

    return 1;
}
