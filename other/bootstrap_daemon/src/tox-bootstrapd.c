/*
 * Tox DHT bootstrap daemon.
 * Main file.
 */

/*
 * Copyright © 2016-2017 The TokTok team.
 * Copyright © 2014-2016 Tox project.
 *
 * This file is part of Tox, the free peer to peer instant messenger.
 *
 * Tox is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * Tox is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with Tox.  If not, see <http://www.gnu.org/licenses/>.
 */
#define _XOPEN_SOURCE 600

// system provided
#include <sys/stat.h>
#include <unistd.h>

// C
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

// toxcore
#include "../../../toxcore/tox.h"
#include "../../../toxcore/LAN_discovery.h"
#include "../../../toxcore/TCP_server.h"
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
        index += sprintf(buffer + index, "%02hhX", public_key[i]);
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

    char *pid_file_path, *keys_file_path;
    int port;
    int enable_ipv6;
    int enable_ipv4_fallback;
    int enable_lan_discovery;
    int enable_tcp_relay;
    uint16_t *tcp_relay_ports;
    int tcp_relay_port_count;
    int enable_motd;
    char *motd;

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
        return 1;
    }

    if (!run_in_foreground) {
        daemonize(log_backend, pid_file_path);
    }

    free(pid_file_path);

    IP ip;
    ip_init(&ip, enable_ipv6);

    Networking_Core *net = new_networking(nullptr, ip, port);

    if (net == nullptr) {
        if (enable_ipv6 && enable_ipv4_fallback) {
            log_write(LOG_LEVEL_WARNING, "Couldn't initialize IPv6 networking. Falling back to using IPv4.\n");
            enable_ipv6 = 0;
            ip_init(&ip, enable_ipv6);
            net = new_networking(nullptr, ip, port);

            if (net == nullptr) {
                log_write(LOG_LEVEL_ERROR, "Couldn't fallback to IPv4. Exiting.\n");
                return 1;
            }
        } else {
            log_write(LOG_LEVEL_ERROR, "Couldn't initialize networking. Exiting.\n");
            return 1;
        }
    }

    DHT *dht = new_DHT(nullptr, net, true);

    if (dht == nullptr) {
        log_write(LOG_LEVEL_ERROR, "Couldn't initialize Tox DHT instance. Exiting.\n");
        return 1;
    }

    Onion *onion = new_onion(dht);
    Onion_Announce *onion_a = new_onion_announce(dht);

    if (!(onion && onion_a)) {
        log_write(LOG_LEVEL_ERROR, "Couldn't initialize Tox Onion. Exiting.\n");
        return 1;
    }

    if (enable_motd) {
        if (bootstrap_set_callbacks(dht_get_net(dht), DAEMON_VERSION_NUMBER, (uint8_t *)motd, strlen(motd) + 1) == 0) {
            log_write(LOG_LEVEL_INFO, "Set MOTD successfully.\n");
        } else {
            log_write(LOG_LEVEL_ERROR, "Couldn't set MOTD: %s. Exiting.\n", motd);
            return 1;
        }

        free(motd);
    }

    if (manage_keys(dht, keys_file_path)) {
        log_write(LOG_LEVEL_INFO, "Keys are managed successfully.\n");
    } else {
        log_write(LOG_LEVEL_ERROR, "Couldn't read/write: %s. Exiting.\n", keys_file_path);
        return 1;
    }

    free(keys_file_path);

    TCP_Server *tcp_server = nullptr;

    if (enable_tcp_relay) {
        if (tcp_relay_port_count == 0) {
            log_write(LOG_LEVEL_ERROR, "No TCP relay ports read. Exiting.\n");
            return 1;
        }

        tcp_server = new_TCP_server(enable_ipv6, tcp_relay_port_count, tcp_relay_ports, dht_get_self_secret_key(dht), onion);

        // tcp_relay_port_count != 0 at this point
        free(tcp_relay_ports);

        if (tcp_server != nullptr) {
            log_write(LOG_LEVEL_INFO, "Initialized Tox TCP server successfully.\n");
        } else {
            log_write(LOG_LEVEL_ERROR, "Couldn't initialize Tox TCP server. Exiting.\n");
            return 1;
        }
    }

    if (bootstrap_from_config(cfg_file_path, dht, enable_ipv6)) {
        log_write(LOG_LEVEL_INFO, "List of bootstrap nodes read successfully.\n");
    } else {
        log_write(LOG_LEVEL_ERROR, "Couldn't read list of bootstrap nodes in %s. Exiting.\n", cfg_file_path);
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

    while (1) {
        do_DHT(dht);

        if (enable_lan_discovery && is_timeout(last_LANdiscovery, LAN_DISCOVERY_INTERVAL)) {
            lan_discovery_send(net_htons_port, dht);
            last_LANdiscovery = unix_time();
        }

        if (enable_tcp_relay) {
            do_TCP_server(tcp_server);
        }

        networking_poll(dht_get_net(dht), nullptr);

        if (waiting_for_dht_connection && DHT_isconnected(dht)) {
            log_write(LOG_LEVEL_INFO, "Connected to another bootstrap node successfully.\n");
            waiting_for_dht_connection = 0;
        }

        SLEEP_MILLISECONDS(30);
    }
}
