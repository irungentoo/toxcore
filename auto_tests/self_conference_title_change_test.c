/* self_conference_title_change.c
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

#include "../toxcore/tox.h"
#include "../toxencryptsave/toxencryptsave.h"

#include "helpers.h"

static const char *newtitle = "kitten over darknet";

static void cbtitlechange(Tox *tox, uint32_t conference_number, uint32_t peer_number, const uint8_t *title,
                          size_t length, void *user_data)
{
    if (!memcmp(title, newtitle, tox_conference_get_title_size(tox, conference_number, NULL))) {
        printf("success: title was changed and updated in the conference");
        exit(0);
    }
}

int main(void)
{
    uint32_t conference_number;
    struct Tox_Options *to = tox_options_new(NULL);
    Tox *t;
    TOX_ERR_CONFERENCE_NEW conference_err;
    TOX_ERR_CONFERENCE_TITLE title_err;

    t = tox_new(to, NULL);
    tox_options_free(to);

    tox_callback_conference_title(t, &cbtitlechange);

    if ((conference_number = tox_conference_new(t, &conference_err)) == UINT32_MAX) {
        tox_kill(t);
        fprintf(stderr, "error: could not create new conference, error code %d\n", conference_err);
        return 2;
    }

    tox_iterate(t, NULL);
    c_sleep(tox_iteration_interval(t));

    if (!tox_conference_set_title(t, conference_number, (const uint8_t *)newtitle, strlen(newtitle), &title_err)) {
        tox_kill(t);
        fprintf(stderr, "error: could not set conference title, error code %d\n", title_err);
        return 3;
    }

    tox_iterate(t, NULL);
    c_sleep(tox_iteration_interval(t));
    tox_iterate(t, NULL);

    fprintf(stderr, "error: title was not changed in callback. exiting.\n");

    tox_kill(t);

    return 1;
}
