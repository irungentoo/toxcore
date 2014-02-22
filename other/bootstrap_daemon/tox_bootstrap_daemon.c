/* tox_bootstrap_daemon.c
 *
 * Tox DHT bootstrap node daemon.
 *
 *  Copyright (C) 2014 Tox project All Rights Reserved.
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

#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#include <syslog.h>

#include <stdio.h>
#include <stdlib.h>
#include <libconfig.h>
#include <arpa/inet.h>
#include <string.h>

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "../../toxcore/DHT.h"
#include "../../toxcore/friend_requests.h"
#include "../../toxcore/LAN_discovery.h"

#include "../../testing/misc_tools.c"

#define DAEMON_NAME "tox_bootstrap_daemon"

#define SLEEP_TIME_MILLISECONDS 30
#define sleep usleep(1000*SLEEP_TIME_MILLISECONDS)

#define DEFAULT_PID_FILE_PATH        ".tox_bootstrap_daemon.pid"
#define DEFAULT_KEYS_FILE_PATH       ".tox_bootstrap_daemon.keys"
#define DEFAULT_PORT                 33445
#define DEFAULT_ENABLE_IPV6          0 // 1 - true, 0 - false
#define DEFAULT_ENABLE_LAN_DISCOVERY 1 // 1 - true, 0 - false


// Uses the already existing key or creates one if it didn't exist
//
// retirns 1 on success
//         0 on failure - no keys were read or stored

int manage_keys(DHT *dht, char *keys_file_path)
{
    const uint32_t KEYS_SIZE = crypto_box_PUBLICKEYBYTES + crypto_box_SECRETKEYBYTES;
    uint8_t keys[KEYS_SIZE];
    FILE *keys_file;

    // Check if file exits, proceed to open and load keys
    keys_file = fopen(keys_file_path, "r");

    if (keys_file != NULL) {
        size_t read_size = fread(keys, sizeof(uint8_t), KEYS_SIZE, keys_file);

        if (read_size != KEYS_SIZE) {
            return 0;
        }

        load_keys(dht->c, keys);
    } else {
        // Otherwise save new keys
        new_keys(dht->c);
        save_keys(dht->c, keys);

        keys_file = fopen(keys_file_path, "w");

        size_t write_size = fwrite(keys, sizeof(uint8_t), KEYS_SIZE, keys_file);

        if (write_size != KEYS_SIZE) {
            return 0;
        }
    }

    fclose(keys_file);

    // We want our DHT public key to be the same as our internal one since this is a bootstrap node
    memcpy(dht->self_public_key, dht->c->self_public_key, crypto_box_PUBLICKEYBYTES);
    memcpy(dht->self_secret_key, dht->c->self_secret_key, crypto_box_SECRETKEYBYTES);

    return 1;
}

// Gets general config options
//
// Important: you are responsible for freeing `pid_file_path` and `keys_file_path`
//
// returns 1 on success
//         0 on failure, doesn't modify any data pointed by arguments

int get_general_config(char *cfg_file_path, char **pid_file_path, char **keys_file_path, int *port, int *enable_ipv6,
                       int *enable_lan_discovery)
{
    config_t cfg;

    const char *NAME_PORT                 = "port";
    const char *NAME_PID_FILE_PATH        = "pid_file_path";
    const char *NAME_KEYS_FILE_PATH       = "keys_file_path";
    const char *NAME_ENABLE_IPV6          = "enable_ipv6";
    const char *NAME_ENABLE_LAN_DISCOVERY = "enable_lan_discovery";

    config_init(&cfg);

    // Read the file. If there is an error, report it and exit.
    if (config_read_file(&cfg, cfg_file_path) == CONFIG_FALSE) {
        syslog(LOG_ERR, "%s:%d - %s\n", config_error_file(&cfg), config_error_line(&cfg), config_error_text(&cfg));
        config_destroy(&cfg);
        return 0;
    }

    // Get port
    if (config_lookup_int(&cfg, NAME_PORT, port) == CONFIG_FALSE) {
        syslog(LOG_WARNING, "No '%s' setting in configuration file.\n", NAME_PORT);
        syslog(LOG_WARNING, "Using default '%s': %d\n", NAME_PORT, DEFAULT_PORT);
        *port = DEFAULT_PORT;
    }

    // Get PID file location
    const char *tmp_pid_file;

    if (config_lookup_string(&cfg, NAME_PID_FILE_PATH, &tmp_pid_file) == CONFIG_FALSE) {
        syslog(LOG_WARNING, "No '%s' setting in configuration file.\n", NAME_PID_FILE_PATH);
        syslog(LOG_WARNING, "Using default '%s': %s\n", NAME_PID_FILE_PATH, DEFAULT_PID_FILE_PATH);
        tmp_pid_file = DEFAULT_PID_FILE_PATH;
    }

    *pid_file_path = malloc(strlen(tmp_pid_file) + 1);
    strcpy(*pid_file_path, tmp_pid_file);

    // Get keys file location
    const char *tmp_keys_file;

    if (config_lookup_string(&cfg, NAME_KEYS_FILE_PATH, &tmp_keys_file) == CONFIG_FALSE) {
        syslog(LOG_WARNING, "No '%s' setting in configuration file.\n", NAME_KEYS_FILE_PATH);
        syslog(LOG_WARNING, "Using default '%s': %s\n", NAME_KEYS_FILE_PATH, DEFAULT_KEYS_FILE_PATH);
        tmp_keys_file = DEFAULT_KEYS_FILE_PATH;
    }

    *keys_file_path = malloc(strlen(tmp_keys_file) + 1);
    strcpy(*keys_file_path, tmp_keys_file);

    // Get IPv6 option
    if (config_lookup_bool(&cfg, NAME_ENABLE_IPV6, enable_ipv6) == CONFIG_FALSE) {
        syslog(LOG_WARNING, "No '%s' setting in configuration file.\n", NAME_ENABLE_IPV6);
        syslog(LOG_WARNING, "Using default '%s': %s\n", NAME_ENABLE_IPV6, DEFAULT_ENABLE_IPV6 ? "true" : "false");
        *enable_ipv6 = DEFAULT_ENABLE_IPV6;
    }

    // Get LAN discovery option
    if (config_lookup_bool(&cfg, NAME_ENABLE_LAN_DISCOVERY, enable_lan_discovery) == CONFIG_FALSE) {
        syslog(LOG_WARNING, "No '%s' setting in configuration file.\n", NAME_ENABLE_LAN_DISCOVERY);
        syslog(LOG_WARNING, "Using default '%s': %s\n", NAME_ENABLE_LAN_DISCOVERY,
               DEFAULT_ENABLE_LAN_DISCOVERY ? "true" : "false");
        *enable_lan_discovery = DEFAULT_ENABLE_LAN_DISCOVERY;
    }

    config_destroy(&cfg);

    syslog(LOG_DEBUG, "Successfully read:\n");
    syslog(LOG_DEBUG, "'%s': %s\n", NAME_PID_FILE_PATH,        *pid_file_path);
    syslog(LOG_DEBUG, "'%s': %s\n", NAME_KEYS_FILE_PATH,       *keys_file_path);
    syslog(LOG_DEBUG, "'%s': %d\n", NAME_PORT,                 *port);
    syslog(LOG_DEBUG, "'%s': %s\n", NAME_ENABLE_IPV6,          *enable_ipv6          ? "true" : "false");
    syslog(LOG_DEBUG, "'%s': %s\n", NAME_ENABLE_LAN_DISCOVERY, *enable_lan_discovery ? "true" : "false");

    return 1;
}

// Bootstraps nodes listed in the config file
//
// returns 1 on success, some or no bootstrap nodes were added
//         0 on failure, a error accured while parsing config file

int bootstrap_from_config(char *cfg_file_path, DHT *dht, int enable_ipv6)
{
    const char *NAME_BOOTSTRAP_NODES = "bootstrap_nodes";

    const char *NAME_PUBLIC_KEY = "public_key";
    const char *NAME_PORT       = "port";
    const char *NAME_ADDRESS    = "address";

    config_t cfg;

    config_init(&cfg);

    if (config_read_file(&cfg, cfg_file_path) == CONFIG_FALSE) {
        syslog(LOG_ERR, "%s:%d - %s\n", config_error_file(&cfg), config_error_line(&cfg), config_error_text(&cfg));
        config_destroy(&cfg);
        return 0;
    }

    config_setting_t *node_list = config_lookup(&cfg, NAME_BOOTSTRAP_NODES);

    if (node_list == NULL) {
        syslog(LOG_WARNING, "No '%s' setting in the configuration file. Skipping bootstrapping.\n", NAME_BOOTSTRAP_NODES);
        config_destroy(&cfg);
        return 1;
    }

    if (config_setting_length(node_list) == 0) {
        syslog(LOG_WARNING, "No bootstrap nodes found. Skipping bootstrapping.\n");
        config_destroy(&cfg);
        return 1;
    }

    int bs_port;
    const char *bs_address;
    const char *bs_public_key;

    config_setting_t *node;

    int i = 0;

    while (config_setting_length(node_list)) {

        node = config_setting_get_elem(node_list, 0);

        if (node == NULL) {
            config_destroy(&cfg);
            return 0;
        }

        // Check that all settings are present
        if (config_setting_lookup_string(node, NAME_PUBLIC_KEY, &bs_public_key) == CONFIG_FALSE) {
            syslog(LOG_WARNING, "Bootstrap node #%d: Couldn't find '%s' setting. Skipping the node.\n", i, NAME_PUBLIC_KEY);
            goto next;
        }

        if (config_setting_lookup_int(node, NAME_PORT, &bs_port) == CONFIG_FALSE) {
            syslog(LOG_WARNING, "Bootstrap node #%d: Couldn't find '%s' setting. Skipping the node.\n", i, NAME_PORT);
            goto next;
        }

        if (config_setting_lookup_string(node, NAME_ADDRESS, &bs_address) == CONFIG_FALSE) {
            syslog(LOG_WARNING, "Bootstrap node #%d: Couldn't find '%s' setting. Skipping the node.\n", i, NAME_ADDRESS);
            goto next;
        }

        // Process settings
        if (strlen(bs_public_key) != 64) {
            syslog(LOG_WARNING, "Bootstrap node #%d: Invalid '%s': %s. Skipping the node.\n", i, NAME_PUBLIC_KEY,
                   bs_public_key);
            goto next;
        }

        // not (1 <= port <= 65535)
        if (bs_port < 1 || bs_port > 65535) {
            syslog(LOG_WARNING, "Bootstrap node #%d: Invalid '%s': %d. Skipping the node.\n", i, NAME_PORT, bs_port);
            goto next;
        }

        uint8_t *bs_public_key_bin = hex_string_to_bin((char *)bs_public_key);
        const int address_resolved = DHT_bootstrap_from_address(dht, bs_address, enable_ipv6, htons(bs_port),
                                     bs_public_key_bin);
        free(bs_public_key_bin);

        if (!address_resolved) {
            syslog(LOG_WARNING, "Bootstrap node #%d: Invalid '%s': %s. Skipping the node.\n", i, NAME_ADDRESS, bs_address);
            goto next;
        }

        syslog(LOG_DEBUG, "Successfully added bootstrap node #%d: %s:%d %s\n", i, bs_address, bs_port, bs_public_key);

next:
        // config_setting_lookup_string() allocates string inside and doesn't allow us to free it
        // so in order to reuse `bs_public_key` and `bs_address` we have to remove the element
        // which will cause libconfig to free allocated strings
        config_setting_remove_elem(node_list, 0);
        i++;
    }

    config_destroy(&cfg);

    return 1;
}

// Prints public key

void print_public_key(uint8_t *public_key)
{
    char buffer[64 + 1];
    int index = 0;

    int i;

    for (i = 0; i < 32; i++) {
        if (public_key[i] < 16) {
            index += sprintf(buffer + index, "0");
        }

        index += sprintf(buffer + index, "%hhX", public_key[i]);
    }

    syslog(LOG_INFO, "Public Key: %s\n", buffer);

    return;
}

int main(int argc, char *argv[])
{
    openlog(DAEMON_NAME, LOG_NOWAIT | LOG_PID, LOG_DAEMON);

    if (argc < 2) {
        syslog(LOG_ERR, "Please specify a path to a configuration file as the first argument. Exiting.\n");
        return 1;
    }

    char *cfg_file_path = argv[1];
    char *pid_file_path, *keys_file_path;
    int port;
    int enable_ipv6;
    int enable_lan_discovery;

    if (get_general_config(cfg_file_path, &pid_file_path, &keys_file_path, &port, &enable_ipv6, &enable_lan_discovery)) {
        syslog(LOG_DEBUG, "General config read successfully\n");
    } else {
        syslog(LOG_ERR, "Couldn't read config file: %s. Exiting.\n", cfg_file_path);
        return 1;
    }

    // not (1 <= port <= 65535)
    if (port < 1 || port > 65535) {
        syslog(LOG_ERR, "Invalid port: %d, must be 1 <= port <= 65535. Exiting.\n", port);
        return 1;
    }

    // Check if the PID file exists
    if (fopen(pid_file_path, "r")) {
        syslog(LOG_ERR, "Another instance of the daemon is already running, PID file %s exists. Exiting.\n", pid_file_path);
        return 1;
    }

    IP ip;
    ip_init(&ip, enable_ipv6);

    DHT *dht = new_DHT(new_net_crypto(new_networking(ip, port)));

    if (dht == NULL) {
        syslog(LOG_ERR, "Couldn't initialize Tox DHT instance. Exiting.\n");
        return 1;
    }

    Onion *onion = new_onion(dht);
    Onion_Announce *onion_a = new_onion_announce(dht);

    if (!(onion && onion_a)) {
        syslog(LOG_ERR, "Couldn't initialize Tox Onion. Exiting.\n");
        return 1;
    }

    if (enable_lan_discovery) {
        LANdiscovery_init(dht);
    }

    if (manage_keys(dht, keys_file_path)) {
        syslog(LOG_DEBUG, "Keys are managed successfully\n");
    } else {
        syslog(LOG_ERR, "Couldn't read/write: %s. Exiting.\n", keys_file_path);
        return 1;
    }

    if (bootstrap_from_config(cfg_file_path, dht, enable_ipv6)) {
        syslog(LOG_DEBUG, "List of bootstrap nodes read successfully\n");
    } else {
        syslog(LOG_ERR, "Couldn't read list of bootstrap nodes in %s. Exiting.\n", cfg_file_path);
        return 1;
    }

    print_public_key(dht->c->self_public_key);

    // Write the PID file
    FILE *pidf = fopen(pid_file_path, "w");

    if (pidf == NULL) {
        syslog(LOG_ERR, "Can't open the PID file for writing: %s. Exiting.\n", pid_file_path);
        return 1;
    }

    free(pid_file_path);
    free(keys_file_path);

    // Fork off from the parent process
    pid_t pid = fork();

    if (pid < 0) {
        fclose(pidf);
        syslog(LOG_ERR, "Forking failed. Exiting.\n");
        return 1;
    }

    if (pid > 0) {
        fprintf(pidf, "%d\n", pid);
        fclose(pidf);
        syslog(LOG_DEBUG, "Forked successfully: PID: %d.\n", pid);
        return 0;
    }

    // Change the file mode mask
    umask(0);

    // Create a new SID for the child process
    if (setsid() < 0) {
        syslog(LOG_ERR, "SID creation failure. Exiting.\n");
        return 1;
    }

    // Change the current working directory
    if ((chdir("/")) < 0) {
        syslog(LOG_ERR, "Couldn't change working directory to '/'. Exiting.\n");
        return 1;
    }

    // Go quiet
    close(STDOUT_FILENO);
    close(STDIN_FILENO);
    close(STDERR_FILENO);

    uint64_t last_LANdiscovery = 0;
    uint16_t htons_port = htons(port);

    int waiting_for_dht_connection = 1;

    while (1) {
        do_DHT(dht);

        if (enable_lan_discovery && is_timeout(last_LANdiscovery, LAN_DISCOVERY_INTERVAL)) {
            send_LANdiscovery(htons_port, dht);
            last_LANdiscovery = unix_time();
        }

        networking_poll(dht->net);

        if (waiting_for_dht_connection && DHT_isconnected(dht)) {
            syslog(LOG_DEBUG, "Connected to other bootstrap node successfully.\n");
            waiting_for_dht_connection = 0;
        }

        sleep;
    }

    return 1;
}
