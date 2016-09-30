/*  logger.c
 *
 *  Copyright (C) 2013, 2015 Tox project All Rights Reserved.
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

#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>


struct Logger {
    logger_cb *callback;
    void *context;
    void *userdata;
};


/**
 * Public Functions
 */
Logger *logger_new()
{
    return (Logger *)calloc(1, sizeof(Logger));
}

void logger_kill(Logger *log)
{
    free(log);
}

void logger_callback_log(Logger *log, logger_cb *function, void *context, void *userdata)
{
    log->callback = function;
    log->context  = context;
    log->userdata = userdata;
}

void logger_write(Logger *log, LOGGER_LEVEL level, const char *file, int line, const char *func, const char *format,
                  ...)
{
    if (!log || !log->callback) {
        return;
    }

    /* Format message */
    char msg[1024];
    va_list args;
    va_start(args, format);
    vsnprintf(msg, sizeof msg, format, args);
    va_end(args);

    log->callback(log->context, level, file, line, func, msg, log->userdata);
}
