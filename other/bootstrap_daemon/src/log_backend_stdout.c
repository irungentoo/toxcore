/* SPDX-License-Identifier: GPL-3.0-or-later
 * Copyright © 2016-2018 The TokTok team.
 * Copyright © 2015-2016 Tox project.
 */

/*
 * Tox DHT bootstrap daemon.
 * Stdout logging backend.
 */
#include "log_backend_stdout.h"

#include <stdarg.h>
#include <stdio.h>

#include "log.h"

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
