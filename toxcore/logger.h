/* SPDX-License-Identifier: GPL-3.0-or-later
 * Copyright © 2016-2026 The TokTok team.
 * Copyright © 2013 Tox project.
 */

/**
 * Logger abstraction backed by callbacks for writing.
 */
#ifndef C_TOXCORE_TOXCORE_LOGGER_H
#define C_TOXCORE_TOXCORE_LOGGER_H

#include <stdint.h>

#include "attributes.h"
#include "mem.h"

#ifdef __cplusplus
extern "C" {
#endif

#ifndef MIN_LOGGER_LEVEL
#define MIN_LOGGER_LEVEL LOGGER_LEVEL_INFO
#endif /* MIN_LOGGER_LEVEL */

// NOTE: Don't forget to update build system files after modifying the enum.
typedef enum Logger_Level {
    LOGGER_LEVEL_TRACE,
    LOGGER_LEVEL_DEBUG,
    LOGGER_LEVEL_INFO,
    LOGGER_LEVEL_WARNING,
    LOGGER_LEVEL_ERROR,
} Logger_Level;

typedef struct Logger Logger;

typedef void logger_cb(void *_Nullable context, Logger_Level level, const char *_Nonnull file, uint32_t line,
                       const char *_Nonnull func, const char *_Nonnull message, void *_Nullable userdata);

/**
 * Creates a new logger with logging disabled (callback is NULL) by default.
 */
Logger *_Nullable logger_new(const Memory *_Nonnull mem);

/**
 * Frees all resources associated with the logger.
 */
void logger_kill(Logger *_Nullable log);
/**
 * Sets the logger callback. Disables logging if set to NULL.
 * The context parameter is passed to the callback as first argument.
 */
void logger_callback_log(Logger *_Nonnull log, logger_cb *_Nullable function, void *_Nullable context, void *_Nullable userdata);
/** @brief Main write function. If logging is disabled, this does nothing.
 *
 * If the logger is NULL and `NDEBUG` is not defined, this writes to stderr.
 * This behaviour should not be used in production code, but can be useful for
 * temporarily debugging a function that does not have a logger available. It's
 * essentially `fprintf(stderr, ...)`, but with source location.
 *
 * If `NDEBUG` is defined, the NULL logger does nothing.
 */
GNU_PRINTF(6, 7)
void logger_write(const Logger *_Nullable log, Logger_Level level, const char *_Nonnull file, uint32_t line, const char *_Nonnull func, const char *_Nonnull format, ...);

/* @brief Terminate the program with a signal. */
void logger_abort(void);

#define LOGGER_WRITE(log, level, ...)                                            \
    do {                                                                         \
        if (level >= MIN_LOGGER_LEVEL) {                                         \
            logger_write(log, level, __FILE__, __LINE__, __func__, __VA_ARGS__); \
        }                                                                        \
    } while (0)

/* To log with an logger */
#define LOGGER_TRACE(log, ...)   LOGGER_WRITE(log, LOGGER_LEVEL_TRACE, __VA_ARGS__)
#define LOGGER_DEBUG(log, ...)   LOGGER_WRITE(log, LOGGER_LEVEL_DEBUG, __VA_ARGS__)
#define LOGGER_INFO(log, ...)    LOGGER_WRITE(log, LOGGER_LEVEL_INFO, __VA_ARGS__)
#define LOGGER_WARNING(log, ...) LOGGER_WRITE(log, LOGGER_LEVEL_WARNING, __VA_ARGS__)
#define LOGGER_ERROR(log, ...)   LOGGER_WRITE(log, LOGGER_LEVEL_ERROR, __VA_ARGS__)

#define LOGGER_FATAL(log, ...)          \
    do {                                \
        LOGGER_ERROR(log, __VA_ARGS__); \
        logger_abort();                 \
    } while (0)

#define LOGGER_ASSERT(log, cond, ...)              \
    do {                                           \
        if (!(cond)) {                             \
            LOGGER_ERROR(log, "Assertion failed"); \
            LOGGER_FATAL(log, __VA_ARGS__);        \
        }                                          \
    } while (0)

#ifdef __cplusplus
} /* extern "C" */
#endif

#endif /* C_TOXCORE_TOXCORE_LOGGER_H */
