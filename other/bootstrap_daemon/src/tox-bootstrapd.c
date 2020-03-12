/* SPDX-License-Identifier: GPL-3.0-or-later
 * Copyright © 2016-2018 The TokTok team.
 * Copyright © 2014-2016 Tox project.
 */

/*
 * Tox DHT bootstrap daemon.
 * Main file.
 */
#ifndef _XOPEN_SOURCE
#define _XOPEN_SOURCE 600
#endif

// system provided
#include <sys/resource.h>
#include <sys/stat.h>
#include <signal.h> // system header, rather than C, because we need it for POSIX sigaction(2)
#include <unistd.h>

// C
#include <assert.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

// toxcore
#include "../../../toxcore/tox.h"
#include "../../../toxcore/LAN_discovery.h"
#include "../../../toxcore/TCP_server.h"
#include "../../../toxcore/logger.h"
#include "../../../toxcore/mono_time.h"
#include "../../../toxcore/onion_announce.h"
#include "../../../toxcore/util.h"

// misc
#include "../../bootstrap_node_packets.h"

#include "command_line_arguments.h"
#include "config.h"
#include "global.h"
#include "log.h"


#define SLEEP_MILLISECONDS(MS) usleep(1000*MS)

// Uses the already existing key or creates one if it didn't exist
//
// returns 1 on success
//         0 on failure - no keys were read or stored

static int manage_keys(DHT *dht, char *keys_file_path)
{
    enum { KEYS_SIZE = CRYPTO_PUBLIC_KEY_SIZE + CRYPTO_SECRET_KEY_SIZE };
    uint8_t keys[KEYS_SIZE];
    FILE *keys_file;

    // Check if file exits, proceed to open and load keys
    keys_file = fopen(keys_file_path, "r");

    if (keys_file != nullptr) {
        const size_t read_size = fread(keys, sizeof(uint8_t), KEYS_SIZE, keys_file);

        if (read_size != KEYS_SIZE) {
            fclose(keys_file);
            return 0;
        }

        dht_set_self_public_key(dht, keys);
        dht_set_self_secret_key(dht, keys + CRYPTO_PUBLIC_KEY_SIZE);
    } else {
        // Otherwise save new keys
        memcpy(keys, dht_get_self_public_key(dht), CRYPTO_PUBLIC_KEY_SIZE);
        memcpy(keys + CRYPTO_PUBLIC_KEY_SIZE, dht_get_self_secret_key(dht), CRYPTO_SECRET_KEY_SIZE);

        keys_file = fopen(keys_file_path, "w");

        if (!keys_file) {
            return 0;
        }

        const size_t write_size = fwrite(keys, sizeof(uint8_t), KEYS_SIZE, keys_file);

        if (write_size != KEYS_SIZE) {
            fclose(keys_file);
            return 0;
        }
    }

    fclose(keys_file);

    return 1;
}

// Prints public key

static void print_public_key(const uint8_t *public_key)
{
    char buffer[2 * CRYPTO_PUBLIC_KEY_SIZE + 1];
    int index = 0;

    size_t i;

    for (i = 0; i < CRYPTO_PUBLIC_KEY_SIZE; i++) {
        index += sprintf(buffer + index, "%02X", public_key[i]);
    }

    log_write(LOG_LEVEL_INFO, "Public Key: %s\n", buffer);
}

// Demonizes the process, appending PID to the PID file and closing file descriptors based on log backend
// Terminates the application if the daemonization fails.

static void daemonize(LOG_BACKEND log_backend, char *pid_file_path)
{
    // Check if the PID file exists
    FILE *pid_file;

    if ((pid_file = fopen(pid_file_path, "r"))) {
        log_write(LOG_LEVEL_WARNING, "Another instance of the daemon is already running, PID file %s exists.\n", pid_file_path);
        fclose(pid_file);
    }

    // Open the PID file for writing
    pid_file = fopen(pid_file_path, "a+");

    if (pid_file == nullptr) {
        log_write(LOG_LEVEL_ERROR, "Couldn't open the PID file for writing: %s. Exiting.\n", pid_file_path);
        exit(1);
    }

    // Fork off from the parent process
    const pid_t pid = fork();

    if (pid > 0) {
        fprintf(pid_file, "%d", pid);
        fclose(pid_file);
        log_write(LOG_LEVEL_INFO, "Forked successfully: PID: %d.\n", pid);
        exit(0);
    } else {
        fclose(pid_file);
    }

    if (pid < 0) {
        log_write(LOG_LEVEL_ERROR, "Forking failed. Exiting.\n");
        exit(1);
    }

    // Create a new SID for the child process
    if (setsid() < 0) {
        log_write(LOG_LEVEL_ERROR, "SID creation failure. Exiting.\n");
        exit(1);
    }


    // Change the current working directory
    if ((chdir("/")) < 0) {
        log_write(LOG_LEVEL_ERROR, "Couldn't change working directory to '/'. Exiting.\n");
        exit(1);
    }

    // Go quiet
    if (log_backend != LOG_BACKEND_STDOUT) {
        close(STDOUT_FILENO);
        close(STDIN_FILENO);
        close(STDERR_FILENO);
    }
}

// Logs toxcore logger message using our logger facility

static void toxcore_logger_callback(void *context, Logger_Level level, const char *file, int line,
                                    const char *func, const char *message, void *userdata)
{
    LOG_LEVEL log_level;

    switch (level) {
        case LOGGER_LEVEL_TRACE:
            log_level = LOG_LEVEL_INFO;
            break;

        case LOGGER_LEVEL_DEBUG:
            log_level = LOG_LEVEL_INFO;
            break;

        case LOGGER_LEVEL_INFO:
            log_level = LOG_LEVEL_INFO;
            break;

        case LOGGER_LEVEL_WARNING:
            log_level = LOG_LEVEL_WARNING;
            break;

        case LOGGER_LEVEL_ERROR:
            log_level = LOG_LEVEL_ERROR;
            break;

        default:
            log_level = LOG_LEVEL_INFO;
            break;
    }

    log_write(log_level, "%s:%d(%s) %s\n", file, line, func, message);
}

static volatile sig_atomic_t caught_signal = 0;

static void handle_signal(int signum)
{
    caught_signal = signum;
}

int main(int argc, char *argv[])
{
    umask(077);
    char *cfg_file_path;
    LOG_BACKEND log_backend;
    bool run_in_foreground;

    // choose backend for printing command line argument parsing output based on whether the daemon is being run from a terminal
    log_backend = isatty(STDOUT_FILENO) ? LOG_BACKEND_STDOUT : LOG_BACKEND_SYSLOG;

    log_open(log_backend);
    handle_command_line_arguments(argc, argv, &cfg_file_path, &log_backend, &run_in_foreground);
    log_close();

    log_open(log_backend);

    log_write(LOG_LEVEL_INFO, "Running \"%s\" version %lu.\n", DAEMON_NAME, DAEMON_VERSION_NUMBER);

    char *pid_file_path = nullptr;
    char *keys_file_path = nullptr;
    int port;
    int enable_ipv6;
    int enable_ipv4_fallback;
    int enable_lan_discovery;
    int enable_tcp_relay;
    uint16_t *tcp_relay_ports = nullptr;
    int tcp_relay_port_count;
    int enable_motd;
    char *motd = nullptr;

    if (get_general_config(cfg_file_path, &pid_file_path, &keys_file_path, &port, &enable_ipv6, &enable_ipv4_fallback,
                           &enable_lan_discovery, &enable_tcp_relay, &tcp_relay_ports, &tcp_relay_port_count, &enable_motd, &motd)) {
        log_write(LOG_LEVEL_INFO, "General config read successfully\n");
    } else {
        log_write(LOG_LEVEL_ERROR, "Couldn't read config file: %s. Exiting.\n", cfg_file_path);
        return 1;
    }

    if (port < MIN_ALLOWED_PORT || port > MAX_ALLOWED_PORT) {
        log_write(LOG_LEVEL_ERROR, "Invalid port: %d, should be in [%d, %d]. Exiting.\n", port, MIN_ALLOWED_PORT,
                  MAX_ALLOWED_PORT);
        free(motd);
        free(tcp_relay_ports);
        free(keys_file_path);
        free(pid_file_path);
        return 1;
    }

    if (!run_in_foreground) {
        daemonize(log_backend, pid_file_path);
    }

    free(pid_file_path);

    IP ip;
    ip_init(&ip, enable_ipv6);

    Logger *logger = logger_new();

    if (MIN_LOGGER_LEVEL == LOGGER_LEVEL_TRACE || MIN_LOGGER_LEVEL == LOGGER_LEVEL_DEBUG) {
        logger_callback_log(logger, toxcore_logger_callback, nullptr, nullptr);
    }

    Networking_Core *net = new_networking(logger, ip, port);

    if (net == nullptr) {
        if (enable_ipv6 && enable_ipv4_fallback) {
            log_write(LOG_LEVEL_WARNING, "Couldn't initialize IPv6 networking. Falling back to using IPv4.\n");
            enable_ipv6 = 0;
            ip_init(&ip, enable_ipv6);
            net = new_networking(logger, ip, port);

            if (net == nullptr) {
                log_write(LOG_LEVEL_ERROR, "Couldn't fallback to IPv4. Exiting.\n");
                logger_kill(logger);
                free(motd);
                free(tcp_relay_ports);
                free(keys_file_path);
                return 1;
            }
        } else {
            log_write(LOG_LEVEL_ERROR, "Couldn't initialize networking. Exiting.\n");
            logger_kill(logger);
            free(motd);
            free(tcp_relay_ports);
            free(keys_file_path);
            return 1;
        }
    }

    Mono_Time *const mono_time = mono_time_new();

    if (mono_time == nullptr) {
        log_write(LOG_LEVEL_ERROR, "Couldn't initialize monotonic timer. Exiting.\n");
        kill_networking(net);
        logger_kill(logger);
        free(motd);
        free(tcp_relay_ports);
        free(keys_file_path);
        return 1;
    }

    mono_time_update(mono_time);

    DHT *const dht = new_dht(logger, mono_time, net, true);

    if (dht == nullptr) {
        log_write(LOG_LEVEL_ERROR, "Couldn't initialize Tox DHT instance. Exiting.\n");
        mono_time_free(mono_time);
        kill_networking(net);
        logger_kill(logger);
        free(motd);
        free(tcp_relay_ports);
        free(keys_file_path);
        return 1;
    }

    Onion *onion = new_onion(mono_time, dht);

    if (!onion) {
        log_write(LOG_LEVEL_ERROR, "Couldn't initialize Tox Onion. Exiting.\n");
        kill_dht(dht);
        mono_time_free(mono_time);
        kill_networking(net);
        logger_kill(logger);
        free(motd);
        free(tcp_relay_ports);
        free(keys_file_path);
        return 1;
    }

    Onion_Announce *onion_a = new_onion_announce(mono_time, dht);

    if (!onion_a) {
        log_write(LOG_LEVEL_ERROR, "Couldn't initialize Tox Onion Announce. Exiting.\n");
        kill_onion(onion);
        kill_dht(dht);
        mono_time_free(mono_time);
        kill_networking(net);
        logger_kill(logger);
        free(motd);
        free(tcp_relay_ports);
        free(keys_file_path);
        return 1;
    }

    if (enable_motd) {
        if (bootstrap_set_callbacks(dht_get_net(dht), DAEMON_VERSION_NUMBER, (uint8_t *)motd, strlen(motd) + 1) == 0) {
            log_write(LOG_LEVEL_INFO, "Set MOTD successfully.\n");
            free(motd);
        } else {
            log_write(LOG_LEVEL_ERROR, "Couldn't set MOTD: %s. Exiting.\n", motd);
            kill_onion_announce(onion_a);
            kill_onion(onion);
            kill_dht(dht);
            mono_time_free(mono_time);
            kill_networking(net);
            logger_kill(logger);
            free(motd);
            free(tcp_relay_ports);
            free(keys_file_path);
            return 1;
        }
    }

    if (manage_keys(dht, keys_file_path)) {
        log_write(LOG_LEVEL_INFO, "Keys are managed successfully.\n");
        free(keys_file_path);
    } else {
        log_write(LOG_LEVEL_ERROR, "Couldn't read/write: %s. Exiting.\n", keys_file_path);
        kill_onion_announce(onion_a);
        kill_onion(onion);
        kill_dht(dht);
        mono_time_free(mono_time);
        kill_networking(net);
        logger_kill(logger);
        free(tcp_relay_ports);
        free(keys_file_path);
        return 1;
    }

    TCP_Server *tcp_server = nullptr;

    if (enable_tcp_relay) {
        if (tcp_relay_port_count == 0) {
            log_write(LOG_LEVEL_ERROR, "No TCP relay ports read. Exiting.\n");
            kill_onion_announce(onion_a);
            kill_onion(onion);
            kill_dht(dht);
            mono_time_free(mono_time);
            kill_networking(net);
            logger_kill(logger);
            free(tcp_relay_ports);
            return 1;
        }

        tcp_server = new_TCP_server(enable_ipv6, tcp_relay_port_count, tcp_relay_ports, dht_get_self_secret_key(dht), onion);

        free(tcp_relay_ports);

        if (tcp_server != nullptr) {
            log_write(LOG_LEVEL_INFO, "Initialized Tox TCP server successfully.\n");

            struct rlimit limit;

            const rlim_t rlim_suggested = 32768;
            const rlim_t rlim_min = 4096;

            assert(rlim_suggested >= rlim_min);

            if (!getrlimit(RLIMIT_NOFILE, &limit)) {
                if (limit.rlim_cur < limit.rlim_max) {
                    // Some systems have a hard limit of over 1000000 open file descriptors, so let's cap it at something reasonable
                    // so that we don't set it to an unreasonably high number.
                    limit.rlim_cur = limit.rlim_max > rlim_suggested ? rlim_suggested : limit.rlim_max;
                    setrlimit(RLIMIT_NOFILE, &limit);
                }
            }

            if (!getrlimit(RLIMIT_NOFILE, &limit) && limit.rlim_cur < rlim_min) {
                log_write(LOG_LEVEL_WARNING,
                          "Current limit on the number of files this process can open (%ju) is rather low for the proper functioning of the TCP server. "
                          "Consider raising the limit to at least %ju or the recommended %ju. "
                          "Continuing using the current limit (%ju).\n",
                          (uintmax_t)limit.rlim_cur, (uintmax_t)rlim_min, (uintmax_t)rlim_suggested, (uintmax_t)limit.rlim_cur);
            }
        } else {
            log_write(LOG_LEVEL_ERROR, "Couldn't initialize Tox TCP server. Exiting.\n");
            kill_onion_announce(onion_a);
            kill_onion(onion);
            kill_dht(dht);
            mono_time_free(mono_time);
            kill_networking(net);
            logger_kill(logger);
            return 1;
        }
    }

    if (bootstrap_from_config(cfg_file_path, dht, enable_ipv6)) {
        log_write(LOG_LEVEL_INFO, "List of bootstrap nodes read successfully.\n");
    } else {
        log_write(LOG_LEVEL_ERROR, "Couldn't read list of bootstrap nodes in %s. Exiting.\n", cfg_file_path);
        kill_TCP_server(tcp_server);
        kill_onion_announce(onion_a);
        kill_onion(onion);
        kill_dht(dht);
        mono_time_free(mono_time);
        kill_networking(net);
        logger_kill(logger);
        return 1;
    }

    print_public_key(dht_get_self_public_key(dht));

    uint64_t last_LANdiscovery = 0;
    const uint16_t net_htons_port = net_htons(port);

    int waiting_for_dht_connection = 1;

    if (enable_lan_discovery) {
        lan_discovery_init(dht);
        log_write(LOG_LEVEL_INFO, "Initialized LAN discovery successfully.\n");
    }

    struct sigaction sa;

    sa.sa_handler = handle_signal;

    // Try to restart interrupted system calls if they are restartable
    sa.sa_flags = SA_RESTART;

    // Prevent the signal handler from being called again before it returns
    sigfillset(&sa.sa_mask);

    if (sigaction(SIGINT, &sa, nullptr)) {
        log_write(LOG_LEVEL_WARNING, "Couldn't set signal handler for SIGINT. Continuing without the signal handler set.\n");
    }

    if (sigaction(SIGTERM, &sa, nullptr)) {
        log_write(LOG_LEVEL_WARNING, "Couldn't set signal handler for SIGTERM. Continuing without the signal handler set.\n");
    }

    while (!caught_signal) {
        mono_time_update(mono_time);

        do_dht(dht);

        if (enable_lan_discovery && mono_time_is_timeout(mono_time, last_LANdiscovery, LAN_DISCOVERY_INTERVAL)) {
            lan_discovery_send(net_htons_port, dht);
            last_LANdiscovery = mono_time_get(mono_time);
        }

        if (enable_tcp_relay) {
            do_TCP_server(tcp_server, mono_time);
        }

        networking_poll(dht_get_net(dht), nullptr);

        if (waiting_for_dht_connection && dht_isconnected(dht)) {
            log_write(LOG_LEVEL_INFO, "Connected to another bootstrap node successfully.\n");
            waiting_for_dht_connection = 0;
        }

        SLEEP_MILLISECONDS(30);
    }

    switch (caught_signal) {
        case SIGINT:
            log_write(LOG_LEVEL_INFO, "Received SIGINT (%d) signal. Exiting.\n", SIGINT);
            break;

        case SIGTERM:
            log_write(LOG_LEVEL_INFO, "Received SIGTERM (%d) signal. Exiting.\n", SIGTERM);
            break;

        default:
            log_write(LOG_LEVEL_INFO, "Received (%d) signal. Exiting.\n", caught_signal);
    }

    if (enable_lan_discovery) {
        lan_discovery_kill(dht);
    }

    kill_TCP_server(tcp_server);
    kill_onion_announce(onion_a);
    kill_onion(onion);
    kill_dht(dht);
    mono_time_free(mono_time);
    kill_networking(net);
    logger_kill(logger);

    return 0;
}
