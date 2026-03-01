/* SPDX-License-Identifier: GPL-3.0-or-later
 * Copyright © 2016-2026 The TokTok team.
 * Copyright © 2015-2016 Tox project.
 */

/*
 * Tox DHT bootstrap daemon.
 * Logging utility with support of multiple logging backends.
 */
#ifndef C_TOXCORE_OTHER_BOOTSTRAP_DAEMON_SRC_LOG_H
#define C_TOXCORE_OTHER_BOOTSTRAP_DAEMON_SRC_LOG_H

#include <stdbool.h>

#include "../../../toxcore/attributes.h"

typedef enum LOG_BACKEND {
    LOG_BACKEND_STDOUT,
    LOG_BACKEND_SYSLOG
} LOG_BACKEND;

typedef enum LOG_LEVEL {
    LOG_LEVEL_TRACE,
    LOG_LEVEL_INFO,
    LOG_LEVEL_WARNING,
    LOG_LEVEL_ERROR
} LOG_LEVEL;

/**
 * Enables or disables logging of trace messages from toxcore.
 * @param enable true to enable, false to disable.
 */
void log_enable_trace(bool enable);

/**
 * Initializes logger.
 * @param backend Specifies which backend to use.
 * @return true on success, false if log is already opened.
 */
bool log_open(LOG_BACKEND backend);

/**
 * Releases all used resources by the logger.
 * @return true on success, false if log is already closed.
 */
bool log_close(void);

/**
 * Writes a message to the log.
 * @param level Log level to use.
 * @param format printf-like format string.
 * @param ... Zero or more arguments, similar to printf function.
 * @return true on success, false if log is closed.
 */
bool log_write(LOG_LEVEL level, const char *category, const char *file, int line, const char *format, ...) GNU_PRINTF(5, 6);

enum {
    LOG_PATH_PREFIX = sizeof(__FILE__) - sizeof("log.h")
};

#define LOG_WRITEC(level, category, ...) log_write(level, category, &__FILE__[LOG_PATH_PREFIX], __LINE__, __VA_ARGS__)
#define LOG_WRITE(level, ...) LOG_WRITEC(level, "tox.bootstrap", __VA_ARGS__)

#endif // C_TOXCORE_OTHER_BOOTSTRAP_DAEMON_SRC_LOG_H
