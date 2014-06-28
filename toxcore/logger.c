/*  logger.c
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

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif /* HAVE_CONFIG_H */

#include "logger.h"

#ifdef LOGGING

#include "network.h" /* for time */

#include <stdio.h>
#include <errno.h>
#include <stdlib.h>
#include <stdarg.h>
#include <inttypes.h>
#include <time.h>

#if defined(_WIN32) || defined(__WIN32__) || defined (WIN32)
#define strerror_r(errno,buf,len) strerror_s(buf,len,errno)
#endif

static struct logger_config {
    FILE *log_file;
    LoggerLevel level;
    uint64_t start_time; /* Time when lib loaded */
}
logger = {
    NULL,
    DEBUG,
    0
};

void __attribute__((destructor)) terminate_logger()
{
    if ( !logger.log_file ) return;

    time_t tim = time(NULL);

    logger_write(ERROR, "\n============== Closing logger [%u] ==============\n"
                 "Time: %s", logger_get_pid(), asctime(localtime(&tim)));

    fclose(logger.log_file);
}

unsigned logger_get_pid()
{
    return
#if defined(_WIN32) || defined(__WIN32__) || defined (WIN32)
        GetCurrentProcessId();
#else
        getpid();
#endif
}

const char *logger_stringify_level(LoggerLevel level)
{
    static const char *strings [] = {
        "INFO",
        "DEBUG",
        "WARNING",
        "ERROR"
    };

    return strings[level];
}


int logger_init(const char *file_name, LoggerLevel level)
{
    char *final_l = calloc(sizeof(char), strlen(file_name) + 32);
    sprintf(final_l, "%s"/*.%u"*/, file_name/*, logger_get_pid()*/);

    if ( logger.log_file ) {
        fprintf(stderr, "Error opening logger name: %s with level %d: file already opened!\n", final_l, level);
        free (final_l);
        return -1;
    }

    logger.log_file = fopen(final_l, "ab");

    if ( logger.log_file == NULL ) {
        fprintf(stderr, "Error opening logger file: %s; info: %s\n", final_l, strerror(errno));

        free (final_l);
        return -1;
    }


    logger.level = level;
    logger.start_time = current_time_monotonic();


    time_t tim = time(NULL);
    logger_write(ERROR, "\n============== Starting logger [%u] ==============\n"
                 "Time: %s", logger_get_pid(), asctime(localtime(&tim)));



    free (final_l);
    return 0;
}


void logger_write (LoggerLevel level, const char *format, ...)
{
    if (logger.log_file == NULL) {
        /*fprintf(stderr, "Logger file is NULL!\n");*/
        return;
    }

    if (logger.level > level) return; /* Don't print some levels xuh */

    va_list _arg;
    va_start (_arg, format);
    vfprintf (logger.log_file, format, _arg);
    va_end (_arg);

    fflush(logger.log_file);
}

char *logger_timestr(char *dest, size_t max_size)
{
    uint64_t diff = (current_time_monotonic() - logger.start_time); /* ms */
    snprintf(dest, max_size, "%"PRIu64"", diff);

    return dest;
}


#endif /* LOGGING */
