/*
 * Tox DHT bootstrap daemon.
 * Stdout logging backend.
 */

/*
 * Copyright © 2016-2017 The TokTok team.
 * Copyright © 2015-2016 Tox project.
 *
 * This file is part of Tox, the free peer to peer instant messenger.
 *
 * Tox is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * Tox is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with Tox.  If not, see <http://www.gnu.org/licenses/>.
 */
#include "log_backend_stdout.h"

#include <stdio.h>

static FILE *log_backend_stdout_level(LOG_LEVEL level)
{
    switch (level) {
        case LOG_LEVEL_INFO:
            return stdout;

        case LOG_LEVEL_WARNING: // intentional fallthrough
        case LOG_LEVEL_ERROR:
            return stderr;
    }

    return stdout;
}

void log_backend_stdout_write(LOG_LEVEL level, const char *format, va_list args)
{
    vfprintf(log_backend_stdout_level(level), format, args);
    fflush(log_backend_stdout_level(level));
}
