/*  logger.h
 *
 *  Copyright (C) 2013 Tox project All Rights Reserved.
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


#ifndef TOXLOGGER_H
#define TOXLOGGER_H

#include <stdint.h>

#ifndef MIN_LOGGER_LEVEL
#define MIN_LOGGER_LEVEL LOG_INFO
#endif

typedef enum {
    LOG_TRACE,
    LOG_DEBUG,
    LOG_INFO,
    LOG_WARNING,
    LOG_ERROR
} LOGGER_LEVEL;

typedef struct Logger Logger;

typedef void logger_cb(void *context, LOGGER_LEVEL level, const char *file, int line,
                       const char *func, const char *message, void *userdata);

/**
 * Creates a new logger with logging disabled (callback is NULL) by default.
 */
Logger *logger_new();

void logger_kill(Logger *log);

/**
 * Sets the logger callback. Disables logging if set to NULL.
 * The context parameter is passed to the callback as first argument.
 */
void logger_callback_log(Logger *log, logger_cb *function, void *context, void *userdata);

/**
 * Main write function. If logging disabled does nothing.
 */
void logger_write(Logger *log, LOGGER_LEVEL level, const char *file, int line, const char *func, const char *format,
                  ...);


#define LOGGER_WRITE(log, level, ...) \
    do { \
        if (level >= MIN_LOGGER_LEVEL) { \
            logger_write(log, level, __FILE__, __LINE__, __func__, __VA_ARGS__); \
        } \
    } while (0)

/* To log with an logger */
#define LOGGER_TRACE(log, ...)   LOGGER_WRITE(log, LOG_TRACE  , __VA_ARGS__)
#define LOGGER_DEBUG(log, ...)   LOGGER_WRITE(log, LOG_DEBUG  , __VA_ARGS__)
#define LOGGER_INFO(log, ...)    LOGGER_WRITE(log, LOG_INFO   , __VA_ARGS__)
#define LOGGER_WARNING(log, ...) LOGGER_WRITE(log, LOG_WARNING, __VA_ARGS__)
#define LOGGER_ERROR(log, ...)   LOGGER_WRITE(log, LOG_ERROR  , __VA_ARGS__)

#endif /* TOXLOGGER_H */
