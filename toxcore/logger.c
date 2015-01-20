/*  logger.c
 *
 *  Copyright (C) 2013, 2015 Tox project All Rights Reserved.
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
#include "crypto_core.h" /* for random_int() */

#include <stdio.h>
#include <errno.h>
#include <stdlib.h>
#include <stdarg.h>
#include <inttypes.h>
#include <time.h>
#include <pthread.h>

#if defined(_WIN32) || defined(__WIN32__) || defined (WIN32)
#   define getpid() ((unsigned) GetCurrentProcessId())
#   define SFILE(FILE__M) (strrchr(FILE__M, '\\') ? strrchr(FILE__M, '\\') + 1 : FILE__M)
#   define WIN_CR "\r"
#else
#   define SFILE(FILE__M) (strrchr(FILE__M, '/') ? strrchr(FILE__M, '/') + 1 : FILE__M)
#   define WIN_CR ""
#endif


struct logger {
    FILE *log_file;
    LOG_LEVEL level;
    uint64_t start_time; /* Time when lib loaded */
    char *id;

    /* Allocate these once */
    char *tstr;
    char *posstr;
    char *msg;

    /* For thread synchronisation */
    pthread_mutex_t mutex[1];
};

Logger *global = NULL;

const char *LOG_LEVEL_STR [] = {
    [LOG_TRACE]   = "TRACE",
    [LOG_DEBUG]   = "DEBUG",
    [LOG_INFO]    = "INFO" ,
    [LOG_WARNING] = "WARN" ,
    [LOG_ERROR]   = "ERROR",
};

char *strtime(char *dest, size_t max_len)
{
    time_t timer;
    struct tm *tm_info;

    time(&timer);
    tm_info = localtime(&timer);

    strftime(dest, max_len, "%m:%d %H:%M:%S", tm_info);
    return dest;
}


/**
 * Public Functions
 */
Logger *logger_new (const char *file_name, LOG_LEVEL level, const char *id)
{
#ifndef LOGGING /* Disabled */
    return NULL;
#endif

    Logger *retu = calloc(1, sizeof(Logger));

    if (!retu)
        return NULL;

    if ( pthread_mutex_init(retu->mutex, NULL) != 0 ) {
        free(retu);
        return NULL;
    }

    if (!(retu->log_file = fopen(file_name, "ab"))) {
        fprintf(stderr, "Error opening logger file: %s; info: %s" WIN_CR "\n", file_name, strerror(errno));
        free(retu);
        pthread_mutex_destroy(retu->mutex);
        return NULL;
    }

    if (!(retu->tstr = calloc(16, sizeof (char))) ||
            !(retu->posstr = calloc(300, sizeof (char))) ||
            !(retu->msg = calloc(4096, sizeof (char))) )
        goto FAILURE;

    if (id) {
        if (!(retu->id = calloc(strlen(id) + 1, 1)))
            goto FAILURE;

        strcpy(retu->id, id);
    } else {
        if (!(retu->id = malloc(8)))
            goto FAILURE;

        snprintf(retu->id, 8, "%u", random_int());
    }

    retu->level = level;
    retu->start_time = current_time_monotonic();

    fprintf(retu->log_file, "Successfully created and running logger id: %s; time: %s" WIN_CR "\n",
            retu->id, strtime(retu->tstr, 16));

    return retu;

FAILURE:
    fprintf(stderr, "Failed to create logger!" WIN_CR "\n");
    pthread_mutex_destroy(retu->mutex);
    fclose(retu->log_file);
    free(retu->tstr);
    free(retu->posstr);
    free(retu->msg);
    free(retu->id);
    free(retu);
    return NULL;
}

void logger_kill(Logger *log)
{
#ifndef LOGGING /* Disabled */
    return;
#endif

    if (!log)
        return;

    pthread_mutex_lock(log->mutex);
    free(log->id);
    free(log->tstr);
    free(log->posstr);
    free(log->msg);

    if (fclose(log->log_file) != 0 )
        perror("Could not close log file");

    pthread_mutex_unlock(log->mutex);
    pthread_mutex_destroy(log->mutex);

    free(log);
}

void logger_kill_global(void)
{
    logger_kill(global);
    global = NULL;
}

void logger_set_global(Logger *log)
{
#ifndef LOGGING /* Disabled */
    return;
#endif

    global = log;
}

Logger *logger_get_global(void)
{
#ifndef LOGGING /* Disabled */
    return NULL;
#endif

    return global;
}

void logger_write (Logger *log, LOG_LEVEL level, const char *file, int line, const char *format, ...)
{
#ifndef LOGGING /* Disabled */
    return;
#endif

    static const char *logger_format =
        "%s  "   /* Logger id string */
        "%-16s"  /* Time string of format: %m:%d %H:%M:%S */
        "%u  "   /* Thread id */
        "%-5s  " /* Logger lever string */
        "%-20s " /* File:line string */
        "- %s"   /* Output message */
        WIN_CR "\n";    /* Every new print new line */


    Logger *this_log = log ? log : global;

    if (!this_log)
        return;

    /* Don't print levels lesser than set one */
    if (this_log->level > level)
        return;

    pthread_mutex_lock(this_log->mutex);

    /* Set position str */
    snprintf(this_log->posstr, 300, "%s:%d", SFILE(file), line);

    /* Set message */
    va_list args;
    va_start (args, format);
    vsnprintf(this_log->msg, 4096, format, args);
    va_end (args);

    fprintf(this_log->log_file, logger_format, this_log->id, strtime(this_log->tstr, 16), pthread_self(),
            LOG_LEVEL_STR[level], this_log->posstr, this_log->msg);
    fflush(this_log->log_file);

    pthread_mutex_unlock(this_log->mutex);
}
