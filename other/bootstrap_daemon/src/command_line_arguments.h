/* command_line_arguments.h
 *
 * Tox DHT bootstrap daemon.
 * Command line argument handling.
 *
 *  Copyright (C) 2015-2016 Tox project All Rights Reserved.
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

#ifndef COMMAND_LINE_ARGUMENTS_H
#define COMMAND_LINE_ARGUMENTS_H

#include "log.h"

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
void handle_command_line_arguments(int argc, char *argv[], char **cfg_file_path, LOG_BACKEND *log_backend,
                                   bool *run_in_foreground);

#endif // COMMAND_LINE_ARGUMENTS_H
