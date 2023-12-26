/* SPDX-License-Identifier: GPL-3.0-or-later
 * Copyright © 2016-2018 The TokTok team.
 * Copyright © 2015-2016 Tox project.
 */

/*
 * Tox DHT bootstrap daemon.
 * Command line argument handling.
 */
#ifndef C_TOXCORE_OTHER_BOOTSTRAP_DAEMON_SRC_COMMAND_LINE_ARGUMENTS_H
#define C_TOXCORE_OTHER_BOOTSTRAP_DAEMON_SRC_COMMAND_LINE_ARGUMENTS_H

#include "log.h"

typedef enum Cli_Status {
    /** Continue the program. Command line processing completed. */
    CLI_STATUS_OK,
    /** Stop the program with success status. */
    CLI_STATUS_DONE,
    /** Stop the program with error status. */
    CLI_STATUS_ERROR,
} Cli_Status;

/**
 * Handles command line arguments, setting cfg_file_path and log_backend.
 * Terminates the application if incorrect arguments are specified.
 *
 * @param argc Argc passed into main().
 * @param argv Argv passed into main().
 * @param cfg_file_path Sets to the provided by the user config file path.
 * @param log_backend Sets to the provided by the user log backend option.
 * @param run_in_foreground Sets to the provided by the user foreground option.
 */
Cli_Status handle_command_line_arguments(
        int argc, char *argv[], char **cfg_file_path, LOG_BACKEND *log_backend,
        bool *run_in_foreground);

#endif // C_TOXCORE_OTHER_BOOTSTRAP_DAEMON_SRC_COMMAND_LINE_ARGUMENTS_H
