/* logger.h
 *
 * Tox DHT bootstrap daemon.
 *
 *  Copyright (C) 2015 Tox project All Rights Reserved.
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

#ifndef LOGGER_H
#define LOGGER_H

typedef enum LOGGER_BACKEND {
    LOGGER_BACKEND_SYSLOG,
    LOGGER_BACKEND_STDOUT
} LOGGER_BACKEND;

typedef enum LOG_LEVEL {
    LOG_LEVEL_INFO,
    LOG_LEVEL_WARNING,
    LOG_LEVEL_ERROR
} LOG_LEVEL;

typedef struct Logger Logger;

/**
 * Creates new logger.
 * @param backend Specifies which backend the logger should use.
 * @return Logger object on success, NULL on failure.
 */
Logger* new_logger(LOGGER_BACKEND backend);

/**
 * Destroys a logger object, releasing all used resources.
 * @param logger Logger object to destroy.
 */
void kill_logger(Logger* logger);

/**
 * Logs a message.
 * @param logger Logger object to use.
 * @param level Log level to use.
 * @param format printf-like format string.
 * @param ... Zero or more arguments, similar to printf function.
 */
void log(Logger* logger, LOG_LEVEL level, const char *format, ...);


#endif // LOGGER_H
