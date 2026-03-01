/* SPDX-License-Identifier: GPL-3.0-or-later
 * Copyright © 2016-2026 The TokTok team.
 * Copyright © 2015-2016 Tox project.
 */

/*
 * Tox DHT bootstrap daemon.
 * Stdout logging backend.
 */
#include "log_backend_stdout.h"

#include <stdarg.h>
#include <stdio.h>
#include <sys/time.h>

#include "../../../toxcore/ccompat.h"
#include "log.h"

static FILE *log_backend_stdout_level(LOG_LEVEL level)
{
    switch (level) {
        case LOG_LEVEL_TRACE: // intentional fallthrough
        case LOG_LEVEL_INFO:
            return stdout;

        case LOG_LEVEL_WARNING: // intentional fallthrough
        case LOG_LEVEL_ERROR:
            return stderr;
    }

    return stdout;
}

static const char *log_level_string(LOG_LEVEL level)
{
    switch (level) {
        case LOG_LEVEL_TRACE:
            return "Debug";

        case LOG_LEVEL_INFO:
            return "Info";

        case LOG_LEVEL_WARNING:
            return "Warning";

        case LOG_LEVEL_ERROR:
            return "Critical"; // Qt-compatible.
    }

    return "Debug"; // Just in case. Shouldn't happen.
}

// Output bootstrap node log messages in the standard Tox log format:
// [15:02:46.433 UTC] (tox.bootstrap) config.c:444 : Info: Successfully added bootstrap node ...
void log_backend_stdout_write(LOG_LEVEL level, const char *category, const char *file, int line, const char *format, va_list args)
{
    struct timeval tv = {0};
    gettimeofday(&tv, nullptr);

    FILE *stream = log_backend_stdout_level(level);
    fprintf(stream, "[%02d:%02d:%02d.%03d UTC] (%s) %s:%d : %s: ",
            (int)(tv.tv_sec / 3600 % 24), (int)(tv.tv_sec / 60 % 60), (int)(tv.tv_sec % 60), (int)(tv.tv_usec / 1000),
            category, file, line, log_level_string(level));
    vfprintf(stream, format, args);
    fflush(stream);
}
