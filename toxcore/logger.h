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

#include <string.h>

/* In case these are undefined; define 'empty' */
#ifndef LOGGER_OUTPUT_FILE
#   define LOGGER_OUTPUT_FILE ""
#endif

#ifndef LOGGER_LEVEL
#   define LOGGER_LEVEL LOG_ERROR
#endif


typedef enum {
    LOG_TRACE,
    LOG_DEBUG,
    LOG_INFO,
    LOG_WARNING,
    LOG_ERROR
} LOG_LEVEL;

typedef struct logger Logger;

/**
 * Set 'level' as the lowest printable level. If id == NULL, random number is used.
 */
Logger *logger_new (const char *file_name, LOG_LEVEL level, const char *id);

void logger_kill (Logger *log);
void logger_kill_global (void);

/**
 * Global logger setter and getter.
 */
void logger_set_global (Logger *log);
Logger *logger_get_global (void);

/**
 * Main write function. If logging disabled does nothing. If log == NULL uses global logger.
 */
void logger_write (Logger *log, LOG_LEVEL level, const char *file, int line, const char *format, ...);


/* To do some checks or similar only when logging, use this */
#ifdef LOGGING
#   define LOGGER_SCOPE(__SCOPE_DO__) do { __SCOPE_DO__ } while(0)
#   define LOGGER_WRITE(log, level, format, ...) \
            logger_write(log, level, __FILE__, __LINE__, format, ##__VA_ARGS__ )
#else
#   define LOGGER_SCOPE(__SCOPE_DO__) do {} while(0)
#   define LOGGER_WRITE(log, level, format, ...) do {} while(0)
#endif /* LOGGING */

/* To log with an logger */
#define LOGGER_TRACE_(log, format, ...) LOGGER_WRITE(log, LOG_TRACE, format, ##__VA_ARGS__ )
#define LOGGER_DEBUG_(log, format, ...) LOGGER_WRITE(log, LOG_DEBUG, format, ##__VA_ARGS__ )
#define LOGGER_INFO_(log, format, ...) LOGGER_WRITE(log, LOG_INFO, format, ##__VA_ARGS__ )
#define LOGGER_WARNING_(log, format, ...) LOGGER_WRITE(log, LOG_WARNING, format, ##__VA_ARGS__ )
#define LOGGER_ERROR_(log, format, ...) LOGGER_WRITE(log, LOG_ERROR, format, ##__VA_ARGS__ )

/* To log with the global logger */
#define LOGGER_TRACE(format, ...) LOGGER_TRACE_(NULL, format, ##__VA_ARGS__)
#define LOGGER_DEBUG(format, ...) LOGGER_DEBUG_(NULL, format, ##__VA_ARGS__)
#define LOGGER_INFO(format, ...) LOGGER_INFO_(NULL, format, ##__VA_ARGS__)
#define LOGGER_WARNING(format, ...) LOGGER_WARNING_(NULL, format, ##__VA_ARGS__)
#define LOGGER_ERROR(format, ...) LOGGER_ERROR_(NULL, format, ##__VA_ARGS__)


#endif /* TOXLOGGER_H */
