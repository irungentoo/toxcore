/* SPDX-License-Identifier: GPL-3.0-or-later
 * Copyright © 2016-2026 The TokTok team.
 * Copyright © 2015-2016 Tox project.
 */

/*
 * Tox DHT bootstrap daemon.
 * Syslog logging backend.
 */
#ifndef C_TOXCORE_OTHER_BOOTSTRAP_DAEMON_SRC_LOG_BACKEND_SYSLOG_H
#define C_TOXCORE_OTHER_BOOTSTRAP_DAEMON_SRC_LOG_BACKEND_SYSLOG_H

#include <stdarg.h>

#include "../../../toxcore/attributes.h"
#include "log.h"

void log_backend_syslog_open(void);
void log_backend_syslog_close(void);
void log_backend_syslog_write(LOG_LEVEL level, const char *category, const char *file, int line, const char *format, va_list args) GNU_PRINTF(5, 0);

#endif  // C_TOXCORE_OTHER_BOOTSTRAP_DAEMON_SRC_LOG_BACKEND_SYSLOG_H
