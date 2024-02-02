/* SPDX-License-Identifier: GPL-3.0-or-later
 * Copyright © 2016-2018 The TokTok team.
 * Copyright © 2015-2016 Tox project.
 */

#include <stdarg.h>

/*
 * Tox DHT bootstrap daemon.
 * Logging utility with support of multiple logging backends.
 */
#include "log.h"
#include "log_backend_stdout.h"
#include "log_backend_syslog.h"

#define INVALID_BACKEND ((LOG_BACKEND)-1u)
static LOG_BACKEND current_backend = INVALID_BACKEND;

bool log_open(LOG_BACKEND backend)
{
    if (current_backend != INVALID_BACKEND) {
        return false;
    }

    current_backend = backend;

    switch (current_backend) {
        case LOG_BACKEND_STDOUT:
            // nothing to do here
            break;

        case LOG_BACKEND_SYSLOG:
            log_backend_syslog_open();
            break;
    }

    return true;
}

bool log_close(void)
{
    if (current_backend == INVALID_BACKEND) {
        return false;
    }

    switch (current_backend) {
        case LOG_BACKEND_STDOUT:
            // nothing to do here
            break;

        case LOG_BACKEND_SYSLOG:
            log_backend_syslog_close();
            break;
    }

    current_backend = INVALID_BACKEND;

    return true;
}

bool log_write(LOG_LEVEL level, const char *format, ...)
{
    if (current_backend == INVALID_BACKEND) {
        return false;
    }

    va_list args;
    va_start(args, format);

    switch (current_backend) {
        case LOG_BACKEND_STDOUT:
            log_backend_stdout_write(level, format, args);
            break;

        case LOG_BACKEND_SYSLOG:
            log_backend_syslog_write(level, format, args);
            break;
    }

    va_end(args);

    return true;
}
