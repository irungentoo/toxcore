/* SPDX-License-Identifier: GPL-3.0-or-later
 * Copyright © 2016-2024 The TokTok team.
 * Copyright © 2014-2016 Tox project.
 */

/*
 * Tox DHT bootstrap daemon.
 * Functionality related to dealing with the config file.
 */
#ifndef C_TOXCORE_OTHER_BOOTSTRAP_DAEMON_SRC_CONFIG_H
#define C_TOXCORE_OTHER_BOOTSTRAP_DAEMON_SRC_CONFIG_H

#include "../../../toxcore/DHT.h"

/**
 * Gets general config options from the config file.
 *
 * Important: You are responsible for freeing `pid_file_path` and `keys_file_path`
 *            also, iff `tcp_relay_ports_count` > 0, then you are responsible for freeing `tcp_relay_ports`
 *            and also `motd` iff `enable_motd` is set.
 *
 * @return 1 on success,
 *         0 on failure, doesn't modify any data pointed by arguments.
 */
int get_general_config(const char *cfg_file_path, char **pid_file_path, char **keys_file_path, int *port,
                       int *enable_ipv6, int *enable_ipv4_fallback, int *enable_lan_discovery, int *enable_tcp_relay,
                       uint16_t **tcp_relay_ports, int *tcp_relay_port_count, int *enable_motd, char **motd);

/**
 * Bootstraps off nodes listed in the config file.
 *
 * @return 1 on success, some or no bootstrap nodes were added
 *         0 on failure, an error occurred while parsing the config file.
 */
int bootstrap_from_config(const char *cfg_file_path, DHT *dht, int enable_ipv6);

#endif // C_TOXCORE_OTHER_BOOTSTRAP_DAEMON_SRC_CONFIG_H
