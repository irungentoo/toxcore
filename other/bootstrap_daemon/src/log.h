/* SPDX-License-Identifier: GPL-3.0-or-later
 * Copyright © 2016-2018 The TokTok team.
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
    LOG_LEVEL_INFO,
    LOG_LEVEL_WARNING,
    LOG_LEVEL_ERROR
} LOG_LEVEL;

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
bool log_write(LOG_LEVEL level, const char *format, ...) GNU_PRINTF(2, 3);

#endif // C_TOXCORE_OTHER_BOOTSTRAP_DAEMON_SRC_LOG_H
