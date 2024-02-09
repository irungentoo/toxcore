/* SPDX-License-Identifier: GPL-3.0-or-later
 * Copyright © 2016-2018 The TokTok team.
 * Copyright © 2015-2016 Tox project.
 */

/*
 * Tox DHT bootstrap daemon.
 * Syslog logging backend.
 */
#include "log_backend_syslog.h"

#include "global.h"
#include "log.h"

#include "../../../toxcore/ccompat.h"

#include <assert.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
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
    const int size = vsnprintf(nullptr, 0, format, args2);
    va_end(args2);

    assert(size >= 0);

    if (size < 0) {
        return;
    }

    char *buf = (char *)malloc(size + 1);
    if (buf == nullptr) {
        return;
    }
    vsnprintf(buf, size + 1, format, args);

    syslog(log_backend_syslog_level(level), "%s", buf);
    free(buf);
}
