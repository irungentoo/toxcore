/* SPDX-License-Identifier: GPL-3.0-or-later
 * Copyright © 2022-2026 The TokTok team.
 */

#ifndef C_TOXCORE_TOXCORE_TOX_LOG_LEVEL_H
#define C_TOXCORE_TOXCORE_TOX_LOG_LEVEL_H

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @brief Severity level of log messages.
 */
typedef enum Tox_Log_Level {
    /**
     * Very detailed traces including all network activity.
     */
    TOX_LOG_LEVEL_TRACE,

    /**
     * Debug messages such as which port we bind to.
     */
    TOX_LOG_LEVEL_DEBUG,

    /**
     * Informational log messages such as video call status changes.
     */
    TOX_LOG_LEVEL_INFO,

    /**
     * Warnings about internal inconsistency or logic errors.
     */
    TOX_LOG_LEVEL_WARNING,

    /**
     * Severe unexpected errors caused by external or internal inconsistency.
     */
    TOX_LOG_LEVEL_ERROR,
} Tox_Log_Level;

const char *tox_log_level_to_string(Tox_Log_Level value);

//!TOKSTYLE-
#ifndef DOXYGEN_IGNORE

#ifndef TOX_HIDE_DEPRECATED
typedef Tox_Log_Level TOX_LOG_LEVEL;
#endif /* TOX_HIDE_DEPRECATED */

#endif
//!TOKSTYLE+

#ifdef __cplusplus
} /* extern "C" */
#endif

#endif /* C_TOXCORE_TOXCORE_TOX_LOG_LEVEL_H */
