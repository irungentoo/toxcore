/* config.h
 *
 * Tox DHT bootstrap daemon.
 * Functionality related to dealing with the config file.
 *
 *  Copyright (C) 2014-2016 Tox project All Rights Reserved.
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

#ifndef CONFIG_H
#define CONFIG_H

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
 *         0 on failure, a error accured while parsing config file.
 */
int bootstrap_from_config(const char *cfg_file_path, DHT *dht, int enable_ipv6);

#endif // CONFIG_H
