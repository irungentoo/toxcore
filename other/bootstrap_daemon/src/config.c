/* SPDX-License-Identifier: GPL-3.0-or-later
 * Copyright © 2016-2024 The TokTok team.
 * Copyright © 2014-2016 Tox project.
 */

/*
 * Tox DHT bootstrap daemon.
 * Functionality related to dealing with the config file.
 */
#include "config.h"

#include "config_defaults.h"
#include "global.h"
#include "log.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <libconfig.h>

#include "../../../toxcore/DHT.h"
#include "../../../toxcore/ccompat.h"
#include "../../../toxcore/crypto_core.h"
#include "../../../toxcore/network.h"
#include "../../bootstrap_node_packets.h"

/**
 * Parses tcp relay ports from `cfg` and puts them into `tcp_relay_ports` array.
 *
 * Supposed to be called from get_general_config only.
 *
 * Important: iff `tcp_relay_port_count` > 0, then you are responsible for freeing `tcp_relay_ports`.
 */
static void parse_tcp_relay_ports_config(config_t *cfg, uint16_t **tcp_relay_ports, int *tcp_relay_port_count)
{
    const char *const NAME_TCP_RELAY_PORTS = "tcp_relay_ports";

    *tcp_relay_port_count = 0;

    config_setting_t *ports_array = config_lookup(cfg, NAME_TCP_RELAY_PORTS);

    if (ports_array == nullptr) {
        log_write(LOG_LEVEL_WARNING, "No '%s' setting in the configuration file.\n", NAME_TCP_RELAY_PORTS);
        log_write(LOG_LEVEL_WARNING, "Using default '%s':\n", NAME_TCP_RELAY_PORTS);

        uint16_t default_ports[] = {DEFAULT_TCP_RELAY_PORTS};

        // Check to avoid calling malloc(0) later on
        // NOLINTNEXTLINE, clang-tidy: error: suspicious comparison of 'sizeof(expr)' to a constant [bugprone-sizeof-expression,-warnings-as-errors]
        static_assert(sizeof(default_ports) > 0, "At least one default TCP relay port should be provided");

        const size_t default_ports_count = sizeof(default_ports)/sizeof(*default_ports);

        for (size_t i = 0; i < default_ports_count; ++i) {
            log_write(LOG_LEVEL_INFO, "Port #%zu: %u\n", i, default_ports[i]);
        }

        // Similar procedure to the one of reading config file below
        *tcp_relay_ports = (uint16_t *)malloc(default_ports_count * sizeof(uint16_t));

        for (size_t i = 0; i < default_ports_count; ++i) {

            (*tcp_relay_ports)[*tcp_relay_port_count] = default_ports[i];

            if ((*tcp_relay_ports)[*tcp_relay_port_count] < MIN_ALLOWED_PORT
                    || (*tcp_relay_ports)[*tcp_relay_port_count] > MAX_ALLOWED_PORT) {
                log_write(LOG_LEVEL_WARNING, "Port #%zu: Invalid port: %u, should be in [%d, %d]. Skipping.\n", i,
                          (*tcp_relay_ports)[*tcp_relay_port_count], MIN_ALLOWED_PORT, MAX_ALLOWED_PORT);
                continue;
            }

            ++*tcp_relay_port_count;
        }

        // The loop above skips invalid ports, so we adjust the allocated memory size
        if ((*tcp_relay_port_count) > 0) {
            *tcp_relay_ports = (uint16_t *)realloc(*tcp_relay_ports, (*tcp_relay_port_count) * sizeof(uint16_t));
        } else {
            free(*tcp_relay_ports);
            *tcp_relay_ports = nullptr;
        }

        return;
    }

    if (config_setting_is_array(ports_array) == CONFIG_FALSE) {
        log_write(LOG_LEVEL_ERROR, "'%s' setting should be an array. Array syntax: 'setting = [value1, value2, ...]'.\n",
                  NAME_TCP_RELAY_PORTS);
        return;
    }

    int config_port_count = config_setting_length(ports_array);

    if (config_port_count == 0) {
        log_write(LOG_LEVEL_ERROR, "'%s' is empty.\n", NAME_TCP_RELAY_PORTS);
        return;
    }

    *tcp_relay_ports = (uint16_t *)malloc(config_port_count * sizeof(uint16_t));

    for (int i = 0; i < config_port_count; ++i) {
        config_setting_t *elem = config_setting_get_elem(ports_array, i);

        if (elem == nullptr) {
            // It's NULL if `ports_array` is not an array (we have that check earlier) or if `i` is out of range, which should not be
            log_write(LOG_LEVEL_WARNING, "Port #%d: Something went wrong while parsing the port. Stopping reading ports.\n", i);
            break;
        }

        if (config_setting_is_number(elem) == CONFIG_FALSE) {
            log_write(LOG_LEVEL_WARNING, "Port #%d: Not a number. Skipping.\n", i);
            continue;
        }

        (*tcp_relay_ports)[*tcp_relay_port_count] = config_setting_get_int(elem);

        if ((*tcp_relay_ports)[*tcp_relay_port_count] < MIN_ALLOWED_PORT
                || (*tcp_relay_ports)[*tcp_relay_port_count] > MAX_ALLOWED_PORT) {
            log_write(LOG_LEVEL_WARNING, "Port #%d: Invalid port: %u, should be in [%d, %d]. Skipping.\n", i,
                      (*tcp_relay_ports)[*tcp_relay_port_count], MIN_ALLOWED_PORT, MAX_ALLOWED_PORT);
            continue;
        }

        ++*tcp_relay_port_count;
    }

    // The loop above skips invalid ports, so we adjust the allocated memory size
    if ((*tcp_relay_port_count) > 0) {
        *tcp_relay_ports = (uint16_t *)realloc(*tcp_relay_ports, (*tcp_relay_port_count) * sizeof(uint16_t));
    } else {
        free(*tcp_relay_ports);
        *tcp_relay_ports = nullptr;
    }
}

int get_general_config(const char *cfg_file_path, char **pid_file_path, char **keys_file_path, int *port,
                       int *enable_ipv6, int *enable_ipv4_fallback, int *enable_lan_discovery, int *enable_tcp_relay,
                       uint16_t **tcp_relay_ports, int *tcp_relay_port_count, int *enable_motd, char **motd)
{
    config_t cfg;

    const char *const NAME_PORT                 = "port";
    const char *const NAME_PID_FILE_PATH        = "pid_file_path";
    const char *const NAME_KEYS_FILE_PATH       = "keys_file_path";
    const char *const NAME_ENABLE_IPV6          = "enable_ipv6";
    const char *const NAME_ENABLE_IPV4_FALLBACK = "enable_ipv4_fallback";
    const char *const NAME_ENABLE_LAN_DISCOVERY = "enable_lan_discovery";
    const char *const NAME_ENABLE_TCP_RELAY     = "enable_tcp_relay";
    const char *const NAME_ENABLE_MOTD          = "enable_motd";
    const char *const NAME_MOTD                 = "motd";

    config_init(&cfg);

    // Read the file. If there is an error, report it and exit.
    if (config_read_file(&cfg, cfg_file_path) == CONFIG_FALSE) {
        log_write(LOG_LEVEL_ERROR, "%s:%d - %s\n", config_error_file(&cfg), config_error_line(&cfg), config_error_text(&cfg));
        config_destroy(&cfg);
        return 0;
    }

    // Get port
    if (config_lookup_int(&cfg, NAME_PORT, port) == CONFIG_FALSE) {
        log_write(LOG_LEVEL_WARNING, "No '%s' setting in configuration file.\n", NAME_PORT);
        log_write(LOG_LEVEL_WARNING, "Using default '%s': %d\n", NAME_PORT, DEFAULT_PORT);
        *port = DEFAULT_PORT;
    }

    // Get PID file location
    const char *tmp_pid_file;

    if (config_lookup_string(&cfg, NAME_PID_FILE_PATH, &tmp_pid_file) == CONFIG_FALSE) {
        log_write(LOG_LEVEL_WARNING, "No '%s' setting in configuration file.\n", NAME_PID_FILE_PATH);
        log_write(LOG_LEVEL_WARNING, "Using default '%s': %s\n", NAME_PID_FILE_PATH, DEFAULT_PID_FILE_PATH);
        tmp_pid_file = DEFAULT_PID_FILE_PATH;
    }

    const size_t pid_file_path_len = strlen(tmp_pid_file) + 1;
    *pid_file_path = (char *)malloc(pid_file_path_len);
    memcpy(*pid_file_path, tmp_pid_file, pid_file_path_len);

    // Get keys file location
    const char *tmp_keys_file;

    if (config_lookup_string(&cfg, NAME_KEYS_FILE_PATH, &tmp_keys_file) == CONFIG_FALSE) {
        log_write(LOG_LEVEL_WARNING, "No '%s' setting in configuration file.\n", NAME_KEYS_FILE_PATH);
        log_write(LOG_LEVEL_WARNING, "Using default '%s': %s\n", NAME_KEYS_FILE_PATH, DEFAULT_KEYS_FILE_PATH);
        tmp_keys_file = DEFAULT_KEYS_FILE_PATH;
    }

    const size_t keys_file_path_len = strlen(tmp_keys_file) + 1;
    *keys_file_path = (char *)malloc(keys_file_path_len);
    memcpy(*keys_file_path, tmp_keys_file, keys_file_path_len);

    // Get IPv6 option
    if (config_lookup_bool(&cfg, NAME_ENABLE_IPV6, enable_ipv6) == CONFIG_FALSE) {
        log_write(LOG_LEVEL_WARNING, "No '%s' setting in configuration file.\n", NAME_ENABLE_IPV6);
        log_write(LOG_LEVEL_WARNING, "Using default '%s': %s\n", NAME_ENABLE_IPV6, DEFAULT_ENABLE_IPV6 ? "true" : "false");
        *enable_ipv6 = DEFAULT_ENABLE_IPV6;
    }

    // Get IPv4 fallback option
    if (config_lookup_bool(&cfg, NAME_ENABLE_IPV4_FALLBACK, enable_ipv4_fallback) == CONFIG_FALSE) {
        log_write(LOG_LEVEL_WARNING, "No '%s' setting in configuration file.\n", NAME_ENABLE_IPV4_FALLBACK);
        log_write(LOG_LEVEL_WARNING, "Using default '%s': %s\n", NAME_ENABLE_IPV4_FALLBACK,
                  DEFAULT_ENABLE_IPV4_FALLBACK ? "true" : "false");
        *enable_ipv4_fallback = DEFAULT_ENABLE_IPV4_FALLBACK;
    }

    // Get LAN discovery option
    if (config_lookup_bool(&cfg, NAME_ENABLE_LAN_DISCOVERY, enable_lan_discovery) == CONFIG_FALSE) {
        log_write(LOG_LEVEL_WARNING, "No '%s' setting in configuration file.\n", NAME_ENABLE_LAN_DISCOVERY);
        log_write(LOG_LEVEL_WARNING, "Using default '%s': %s\n", NAME_ENABLE_LAN_DISCOVERY,
                  DEFAULT_ENABLE_LAN_DISCOVERY ? "true" : "false");
        *enable_lan_discovery = DEFAULT_ENABLE_LAN_DISCOVERY;
    }

    // Get TCP relay option
    if (config_lookup_bool(&cfg, NAME_ENABLE_TCP_RELAY, enable_tcp_relay) == CONFIG_FALSE) {
        log_write(LOG_LEVEL_WARNING, "No '%s' setting in configuration file.\n", NAME_ENABLE_TCP_RELAY);
        log_write(LOG_LEVEL_WARNING, "Using default '%s': %s\n", NAME_ENABLE_TCP_RELAY,
                  DEFAULT_ENABLE_TCP_RELAY ? "true" : "false");
        *enable_tcp_relay = DEFAULT_ENABLE_TCP_RELAY;
    }

    if (*enable_tcp_relay) {
        parse_tcp_relay_ports_config(&cfg, tcp_relay_ports, tcp_relay_port_count);
    } else {
        *tcp_relay_port_count = 0;
    }

    // Get MOTD option
    if (config_lookup_bool(&cfg, NAME_ENABLE_MOTD, enable_motd) == CONFIG_FALSE) {
        log_write(LOG_LEVEL_WARNING, "No '%s' setting in configuration file.\n", NAME_ENABLE_MOTD);
        log_write(LOG_LEVEL_WARNING, "Using default '%s': %s\n", NAME_ENABLE_MOTD,
                  DEFAULT_ENABLE_MOTD ? "true" : "false");
        *enable_motd = DEFAULT_ENABLE_MOTD;
    }

    if (*enable_motd) {
        // Get MOTD
        const char *tmp_motd;

        if (config_lookup_string(&cfg, NAME_MOTD, &tmp_motd) == CONFIG_FALSE) {
            log_write(LOG_LEVEL_WARNING, "No '%s' setting in configuration file.\n", NAME_MOTD);
            log_write(LOG_LEVEL_WARNING, "Using default '%s': %s\n", NAME_MOTD, DEFAULT_MOTD);
            tmp_motd = DEFAULT_MOTD;
        }

        size_t tmp_motd_length = strlen(tmp_motd) + 1;
        size_t motd_length = tmp_motd_length > MAX_MOTD_LENGTH ? MAX_MOTD_LENGTH : tmp_motd_length;
        *motd = (char *)malloc(motd_length);
        snprintf(*motd, motd_length, "%s", tmp_motd);
    }

    config_destroy(&cfg);

    log_write(LOG_LEVEL_INFO, "Successfully read:\n");
    log_write(LOG_LEVEL_INFO, "'%s': %s\n", NAME_PID_FILE_PATH,        *pid_file_path);
    log_write(LOG_LEVEL_INFO, "'%s': %s\n", NAME_KEYS_FILE_PATH,       *keys_file_path);
    log_write(LOG_LEVEL_INFO, "'%s': %d\n", NAME_PORT,                 *port);
    log_write(LOG_LEVEL_INFO, "'%s': %s\n", NAME_ENABLE_IPV6,          *enable_ipv6          ? "true" : "false");
    log_write(LOG_LEVEL_INFO, "'%s': %s\n", NAME_ENABLE_IPV4_FALLBACK, *enable_ipv4_fallback ? "true" : "false");
    log_write(LOG_LEVEL_INFO, "'%s': %s\n", NAME_ENABLE_LAN_DISCOVERY, *enable_lan_discovery ? "true" : "false");

    log_write(LOG_LEVEL_INFO, "'%s': %s\n", NAME_ENABLE_TCP_RELAY,     *enable_tcp_relay     ? "true" : "false");

    // Show info about tcp ports only if tcp relay is enabled
    if (*enable_tcp_relay) {
        if (*tcp_relay_port_count == 0) {
            log_write(LOG_LEVEL_ERROR, "No TCP ports could be read.\n");
        } else {
            log_write(LOG_LEVEL_INFO, "Read %d TCP ports:\n", *tcp_relay_port_count);

            for (int i = 0; i < *tcp_relay_port_count; ++i) {
                log_write(LOG_LEVEL_INFO, "Port #%d: %u\n", i, (*tcp_relay_ports)[i]);
            }
        }
    }

    log_write(LOG_LEVEL_INFO, "'%s': %s\n", NAME_ENABLE_MOTD,          *enable_motd          ? "true" : "false");

    if (*enable_motd) {
        log_write(LOG_LEVEL_INFO, "'%s': %s\n", NAME_MOTD, *motd);
    }

    return 1;
}

/**
 *
 * Converts a hex string with even number of characters into binary.
 *
 * Important: You are responsible for freeing the return value.
 *
 * @return binary on success,
 *         NULL on failure.
 */
static uint8_t *bootstrap_hex_string_to_bin(const char *hex_string)
{
    if (strlen(hex_string) % 2 != 0) {
        return nullptr;
    }

    size_t len = strlen(hex_string) / 2;
    uint8_t *ret = (uint8_t *)malloc(len);

    const char *pos = hex_string;

    for (size_t i = 0; i < len; ++i, pos += 2) {
        unsigned int val;
        sscanf(pos, "%02x", &val);
        ret[i] = val;
    }

    return ret;
}

int bootstrap_from_config(const char *cfg_file_path, DHT *dht, int enable_ipv6)
{
    const char *const NAME_BOOTSTRAP_NODES = "bootstrap_nodes";

    const char *const NAME_PUBLIC_KEY = "public_key";
    const char *const NAME_PORT       = "port";
    const char *const NAME_ADDRESS    = "address";

    config_t cfg;

    config_init(&cfg);

    if (config_read_file(&cfg, cfg_file_path) == CONFIG_FALSE) {
        log_write(LOG_LEVEL_ERROR, "%s:%d - %s\n", config_error_file(&cfg), config_error_line(&cfg), config_error_text(&cfg));
        config_destroy(&cfg);
        return 0;
    }

    config_setting_t *node_list = config_lookup(&cfg, NAME_BOOTSTRAP_NODES);

    if (node_list == nullptr) {
        log_write(LOG_LEVEL_WARNING, "No '%s' setting in the configuration file. Skipping bootstrapping.\n",
                  NAME_BOOTSTRAP_NODES);
        config_destroy(&cfg);
        return 1;
    }

    if (config_setting_length(node_list) == 0) {
        log_write(LOG_LEVEL_WARNING, "No bootstrap nodes found. Skipping bootstrapping.\n");
        config_destroy(&cfg);
        return 1;
    }

    int bs_port;
    const char *bs_address;
    const char *bs_public_key;

    config_setting_t *node;

    int i = 0;

    while (config_setting_length(node_list)) {
        int address_resolved;
        uint8_t *bs_public_key_bin;

        node = config_setting_get_elem(node_list, 0);

        if (node == nullptr) {
            config_destroy(&cfg);
            return 0;
        }

        // Check that all settings are present
        if (config_setting_lookup_string(node, NAME_PUBLIC_KEY, &bs_public_key) == CONFIG_FALSE) {
            log_write(LOG_LEVEL_WARNING, "Bootstrap node #%d: Couldn't find '%s' setting. Skipping the node.\n", i,
                      NAME_PUBLIC_KEY);
            goto next;
        }

        if (config_setting_lookup_int(node, NAME_PORT, &bs_port) == CONFIG_FALSE) {
            log_write(LOG_LEVEL_WARNING, "Bootstrap node #%d: Couldn't find '%s' setting. Skipping the node.\n", i, NAME_PORT);
            goto next;
        }

        if (config_setting_lookup_string(node, NAME_ADDRESS, &bs_address) == CONFIG_FALSE) {
            log_write(LOG_LEVEL_WARNING, "Bootstrap node #%d: Couldn't find '%s' setting. Skipping the node.\n", i, NAME_ADDRESS);
            goto next;
        }

        // Process settings
        if (strlen(bs_public_key) != CRYPTO_PUBLIC_KEY_SIZE * 2) {
            log_write(LOG_LEVEL_WARNING, "Bootstrap node #%d: Invalid '%s': %s. Skipping the node.\n", i, NAME_PUBLIC_KEY,
                      bs_public_key);
            goto next;
        }

        if (bs_port < MIN_ALLOWED_PORT || bs_port > MAX_ALLOWED_PORT) {
            log_write(LOG_LEVEL_WARNING, "Bootstrap node #%d: Invalid '%s': %d, should be in [%d, %d]. Skipping the node.\n", i,
                      NAME_PORT,
                      bs_port, MIN_ALLOWED_PORT, MAX_ALLOWED_PORT);
            goto next;
        }

        bs_public_key_bin = bootstrap_hex_string_to_bin(bs_public_key);
        address_resolved = dht_bootstrap_from_address(dht, bs_address, enable_ipv6, net_htons(bs_port),
                           bs_public_key_bin);
        free(bs_public_key_bin);

        if (!address_resolved) {
            log_write(LOG_LEVEL_WARNING, "Bootstrap node #%d: Invalid '%s': %s. Skipping the node.\n", i, NAME_ADDRESS, bs_address);
            goto next;
        }

        log_write(LOG_LEVEL_INFO, "Successfully added bootstrap node #%d: %s:%d %s\n", i, bs_address, bs_port, bs_public_key);

next:
        // config_setting_lookup_string() allocates string inside and doesn't allow us to free it directly
        // though it's freed when the element is removed, so we free it right away in order to keep memory
        // consumption minimal
        config_setting_remove_elem(node_list, 0);
        ++i;
    }

    config_destroy(&cfg);

    return 1;
}
