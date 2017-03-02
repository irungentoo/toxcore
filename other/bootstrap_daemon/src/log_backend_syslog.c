/*
 * Tox DHT bootstrap daemon.
 * Syslog logging backend.
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
#include "log_backend_syslog.h"

#include "global.h"

#include "../../../toxcore/ccompat.h"

#include <assert.h>
#include <stdio.h>
#include <syslog.h>

void log_backend_syslog_open(void)
{
    openlog(DAEMON_NAME, LOG_NOWAIT | LOG_PID, LOG_DAEMON);
}

void log_backend_syslog_close(void)
{
    closelog();
}

static int log_backend_syslog_level(LOG_LEVEL level)
{
    switch (level) {
        case LOG_LEVEL_INFO:
            return LOG_INFO;

        case LOG_LEVEL_WARNING:
            return LOG_WARNING;

        case LOG_LEVEL_ERROR:
            return LOG_ERR;
    }

    return LOG_INFO;
}

void log_backend_syslog_write(LOG_LEVEL level, const char *format, va_list args)
{
    va_list args2;

    va_copy(args2, args);
    int size = vsnprintf(NULL, 0, format, args2);
    va_end(args2);

    assert(size >= 0);

    if (size < 0) {
        return;
    }

    VLA(char, buf, size + 1);
    vsnprintf(buf, size + 1, format, args);

    syslog(log_backend_syslog_level(level), "%s", buf);
}
