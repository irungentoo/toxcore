/* SPDX-License-Identifier: GPL-3.0-or-later
 * Copyright © 2016-2018 The TokTok team.
 * Copyright © 2015-2016 Tox project.
 */

/*
 * Tox DHT bootstrap daemon.
 * Command line argument handling.
 */
#include "command_line_arguments.h"

#include "global.h"

#include "../../../toxcore/ccompat.h"

#include <getopt.h>

#include <stdlib.h>
#include <string.h>


/**
 * Prints --help message
 */
static void print_help(void)
{
    // 2 space ident
    // make sure all lines fit into 80 columns
    // make sure options are listed in alphabetical order
    log_write(LOG_LEVEL_INFO,
              "Usage: tox-bootstrapd [OPTION]... --config=FILE_PATH\n"
              "\n"
              "Options:\n"
              "  --config=FILE_PATH     Specify path to the config file.\n"
              "                         This is a required option.\n"
              "                         Set FILE_PATH to a path to an empty file in order to\n"
              "                         use default settings.\n"
              "  --foreground           Run the daemon in foreground. The daemon won't fork\n"
              "                         (detach from the terminal) and won't use the PID file.\n"
              "  --help                 Print this help message.\n"
              "  --log-backend=BACKEND  Specify which logging backend to use.\n"
              "                         Valid BACKEND values (case sensetive):\n"
              "                           syslog Writes log messages to syslog.\n"
              "                                  Default option when no --log-backend is\n"
              "                                  specified.\n"
              "                           stdout Writes log messages to stdout/stderr.\n"
              "  --version              Print version information.\n");
}

void handle_command_line_arguments(int argc, char *argv[], char **cfg_file_path, LOG_BACKEND *log_backend,
                                   bool *run_in_foreground)
{
    if (argc < 2) {
        log_write(LOG_LEVEL_ERROR, "Error: No arguments provided.\n\n");
        print_help();
        exit(1);
    }

    opterr = 0;

    static const struct option long_options[] = {
        {"config",      required_argument, nullptr, 'c'}, // required option
        {"foreground",  no_argument,       nullptr, 'f'},
        {"help",        no_argument,       nullptr, 'h'},
        {"log-backend", required_argument, nullptr, 'l'}, // optional, defaults to syslog
        {"version",     no_argument,       nullptr, 'v'},
        {nullptr,       0,                 nullptr,  0 }
    };

    bool cfg_file_path_set = false;
    bool log_backend_set   = false;

    *run_in_foreground = false;

    int opt;

    while ((opt = getopt_long(argc, argv, ":", long_options, nullptr)) != -1) {

        switch (opt) {

            case 'c':
                *cfg_file_path = optarg;
                cfg_file_path_set = true;
                break;

            case 'f':
                *run_in_foreground = true;
                break;

            case 'h':
                print_help();
                exit(0);

            case 'l':
                if (strcmp(optarg, "syslog") == 0) {
                    *log_backend = LOG_BACKEND_SYSLOG;
                    log_backend_set = true;
                } else if (strcmp(optarg, "stdout") == 0) {
                    *log_backend = LOG_BACKEND_STDOUT;
                    log_backend_set = true;
                } else {
                    log_write(LOG_LEVEL_ERROR, "Error: Invalid BACKEND value for --log-backend option passed: %s\n\n", optarg);
                    print_help();
                    exit(1);
                }

                break;

            case 'v':
                log_write(LOG_LEVEL_INFO, "Version: %lu\n", DAEMON_VERSION_NUMBER);
                exit(0);

            case '?':
                log_write(LOG_LEVEL_ERROR, "Error: Unrecognized option %s\n\n", argv[optind - 1]);
                print_help();
                exit(1);

            case ':':
                log_write(LOG_LEVEL_ERROR, "Error: No argument provided for option %s\n\n", argv[optind - 1]);
                print_help();
                exit(1);
        }
    }

    if (!log_backend_set) {
        *log_backend = LOG_BACKEND_SYSLOG;
    }

    if (!cfg_file_path_set) {
        log_write(LOG_LEVEL_ERROR, "Error: The required --config option wasn't specified\n\n");
        print_help();
        exit(1);
    }
}
