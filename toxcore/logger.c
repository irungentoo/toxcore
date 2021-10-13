/* SPDX-License-Identifier: GPL-3.0-or-later
 * Copyright © 2016-2018 The TokTok team.
 * Copyright © 2013,2015 Tox project.
 */

/*
 * Text logging abstraction.
 */
#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "logger.h"

#include <assert.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>


struct Logger {
    logger_cb *callback;
    void *context;
    void *userdata;
};

#ifdef USE_STDERR_LOGGER
static const char *logger_level_name(Logger_Level level)
{
    switch (level) {
        case LOGGER_LEVEL_TRACE:
            return "TRACE";

        case LOGGER_LEVEL_DEBUG:
            return "DEBUG";

        case LOGGER_LEVEL_INFO:
            return "INFO";

        case LOGGER_LEVEL_WARNING:
            return "WARNING";

        case LOGGER_LEVEL_ERROR:
            return "ERROR";
    }

    return "<unknown>";
}

static void logger_stderr_handler(void *context, Logger_Level level, const char *file, int line, const char *func,
                                  const char *message, void *userdata)
{
    // GL stands for "global logger".
    fprintf(stderr, "[GL] %s %s:%d(%s): %s\n", logger_level_name(level), file, line, func, message);
}

static const Logger logger_stderr = {
    logger_stderr_handler,
    nullptr,
    nullptr,
};
#endif

/**
 * Public Functions
 */
Logger *logger_new(void)
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

void logger_write(const Logger *log, Logger_Level level, const char *file, int line, const char *func,
                  const char *format, ...)
{
    if (!log) {
#ifdef USE_STDERR_LOGGER
        log = &logger_stderr;
#else
        fprintf(stderr, "NULL logger not permitted.\n");
        abort();
#endif
    }

    if (!log->callback) {
        return;
    }

    // Only pass the file name, not the entire file path, for privacy reasons.
    // The full path may contain PII of the person compiling toxcore (their
    // username and directory layout).
    const char *filename = strrchr(file, '/');
    file = filename ? filename + 1 : file;
#if defined(_WIN32) || defined(__CYGWIN__)
    // On Windows, the path separator *may* be a backslash, so we look for that
    // one too.
    const char *windows_filename = strrchr(file, '\\');
    file = windows_filename ? windows_filename + 1 : file;
#endif

    // Format message
    char msg[1024];
    va_list args;
    va_start(args, format);
    vsnprintf(msg, sizeof(msg), format, args);
    va_end(args);

    log->callback(log->context, level, file, line, func, msg, log->userdata);
}
