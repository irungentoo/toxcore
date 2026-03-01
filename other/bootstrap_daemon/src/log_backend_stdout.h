/* SPDX-License-Identifier: GPL-3.0-or-later
 * Copyright © 2016-2026 The TokTok team.
 * Copyright © 2015-2016 Tox project.
 */

/*
 * Tox DHT bootstrap daemon.
 * Stdout logging backend.
 */
#ifndef C_TOXCORE_OTHER_BOOTSTRAP_DAEMON_SRC_LOG_BACKEND_STDOUT_H
#define C_TOXCORE_OTHER_BOOTSTRAP_DAEMON_SRC_LOG_BACKEND_STDOUT_H

#include <stdarg.h>

#include "../../../toxcore/attributes.h"
#include "log.h"

void log_backend_stdout_write(LOG_LEVEL level, const char *category, const char *file, int line, const char *format, va_list args) GNU_PRINTF(5, 0);

#endif  // C_TOXCORE_OTHER_BOOTSTRAP_DAEMON_SRC_LOG_BACKEND_STDOUT_H
