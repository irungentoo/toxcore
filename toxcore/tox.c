/* tox.c
 *
 * The Tox public API.
 *
 *  Copyright (C) 2013 Tox project All Rights Reserved.
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

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "Messenger.h"
#include "group.h"
#include "logger.h"

#define TOX_DEFINED
typedef struct Messenger Tox;

#include "tox.h"

#define SET_ERROR_PARAMETER(param, x) {if(param) {*param = x;}}

uint32_t tox_version_major(void)
{
    return 0;
}

uint32_t tox_version_minor(void)
{
    return 0;
}

uint32_t tox_version_patch(void)
{
    return 0;
}

bool tox_version_is_compatible(uint32_t major, uint32_t minor, uint32_t patch)
{
    //TODO
    return 1;
}


void tox_options_default(struct Tox_Options *options)
{
    if (options) {
        memset(options, 0, sizeof(struct Tox_Options));
    }
}

struct Tox_Options *tox_options_new(TOX_ERR_OPTIONS_NEW *error)
{
    struct Tox_Options *options = calloc(sizeof(struct Tox_Options), 1);

    if (options) {
        SET_ERROR_PARAMETER(error, TOX_ERR_OPTIONS_NEW_OK);
        return options;
    }

    SET_ERROR_PARAMETER(error, TOX_ERR_OPTIONS_NEW_MALLOC);
    return NULL;
}

void tox_options_free(struct Tox_Options *options)
{
    free(options);
}

Tox *tox_new(struct Tox_Options const *options, uint8_t const *data, size_t length, TOX_ERR_NEW *error)
{

}

void tox_kill(Tox *tox)
{

}


size_t tox_save_size(Tox const *tox)
{

}


void tox_save(Tox const *tox, uint8_t *data)
{

}
