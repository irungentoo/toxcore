/* logger.c
 *
 * Tox DHT bootstrap daemon.
 *
 *  Copyright (C) 2015 Tox project All Rights Reserved.
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

#include "logger.h"

#include "global.h"

#include <syslog.h>

#include <stdarg.h>
#include <stdio.h>

typedef struct Logger {
    LOGGER_BACKEND backend;
} Logger;

Logger* new_logger(LOGGER_BACKEND backend)
{
    if (backend == LOGGER_BACKEND_SYSLOG) {
        openlog(DAEMON_NAME, LOG_NOWAIT | LOG_PID, LOG_DAEMON);
    }

    Logger* logger = malloc(sizeof(Logger));

    if (logger == NULL) {
        return NULL;
    }

    logger->backend = backend;

    return logger;
}

void kill_logger(Logger* logger)
{
    if (backend == LOGGER_BACKEND_SYSLOG) {
        closelog();
    }

    free(logger);
}

int level_syslog(LOG_LEVEL level)
{
    switch (level) {
        case LOG_LEVEL_INFO:
            return LOG_INFO;
        case LOG_LEVEL_WARNING:
            return LOG_WARNING;
        case LOG_LEVEL_ERROR:
            return LOG_ERR;
    }
}

void log_syslog(LOG_LEVEL level, const char *format, va_list args)
{
    vsyslog(level_syslog(level), format, args);
}

FILE* level_stdout(LOG_LEVEL level)
{
    switch (level) {
        case LOG_LEVEL_INFO:
            return stdout;
        case LOG_LEVEL_WARNING: // intentional fallthrough
        case LOG_LEVEL_ERROR:
            return stderr;

    }
}

void log_stdout(LOG_LEVEL level, const char *format, va_list args)
{
    vfprintf(level_stdout(level), format, args);
}

void log(Logger* logger, LOG_LEVEL level, const char *format, ...)
{
    va_list args;
    va_start(args, format);

    switch (logger->backend) {
        case LOGGER_BACKEND_SYSLOG:
            log_syslog(level, format, args);
            break;
        case LOGGER_BACKEND_STDOUT:
            log_stdout(level, format, args);
            break;
    }

    va_end(args);
}
