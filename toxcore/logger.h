/*  logger.h
 *
 *  Wrapping logger functions in nice macros
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


#ifndef __TOXLOGGER
#define __TOXLOGGER

#include <string.h>

#ifdef LOGGING

typedef enum _LoggerLevel {
    INFO,
    DEBUG,
    WARNING,
    ERROR
} LoggerLevel;

/*
 * Set 'level' as the lowest printable level
 */
int logger_init(const char *file_name, LoggerLevel level);
const char *logger_stringify_level(LoggerLevel level);
unsigned logger_get_pid();
void logger_write (LoggerLevel level, const char *format, ...);
char *logger_timestr (char *dest, size_t max_size);

#if defined(_WIN32) || defined(__WIN32__) || defined (WIN32)
#define _SFILE (strrchr(__FILE__, '\\') ? strrchr(__FILE__, '\\') + 1 : __FILE__)
#else
#define _SFILE (strrchr(__FILE__, '/') ? strrchr(__FILE__, '/') + 1 : __FILE__)
#endif

#define WRITE_FORMAT(__LEVEL__, format) char __time__[20]; char* the_str = calloc(sizeof(char), strlen(format)+ 500); sprintf(the_str, "\n[%u] [%s] [%s] [%s:%d %s()] %s", \
                             logger_get_pid(), logger_stringify_level(__LEVEL__), logger_timestr(__time__, 20), _SFILE, __LINE__, __func__, format)

/* Use these macros */

#define LOGGER_INIT(name, level) logger_init(name, level);
#define LOGGER_INFO(format, ...) do { WRITE_FORMAT(INFO, format); logger_write( INFO, the_str, ##__VA_ARGS__ ); free(the_str); } while (0)
#define LOGGER_DEBUG(format, ...) do { WRITE_FORMAT(DEBUG, format); logger_write( DEBUG, the_str, ##__VA_ARGS__ ); free(the_str); } while (0)
#define LOGGER_WARNING(format, ...) do { WRITE_FORMAT(WARNING, format); logger_write( WARNING, the_str, ##__VA_ARGS__ ); free(the_str); } while (0)
#define LOGGER_ERROR(format, ...) do { WRITE_FORMAT(ERROR, format); logger_write( ERROR, the_str, ##__VA_ARGS__ ); free(the_str); } while (0)

/* To do some checks or similar only when logging use this */
#define LOGGER_SCOPE(__SCOPE_DO__) do { __SCOPE_DO__ } while(0)

#else


#define LOGGER_INIT(name, level) do {} while(0)
#define LOGGER_INFO(format, ...) do {} while(0)
#define LOGGER_DEBUG(format, ...) do {} while(0)
#define LOGGER_WARNING(format, ...) do {} while(0)
#define LOGGER_ERROR(format, ...) do {} while(0)

#define LOGGER_SCOPE(__SCOPE_DO__) do {} while(0)

#endif /* LOGGING */




#endif /* __TOXLOGGER */
