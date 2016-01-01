/* config_defaults.h
 *
 * Tox DHT bootstrap daemon.
 * Default config options for when they are missing in the config file.
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

#ifndef CONFIG_DEFAULTS_H
#define CONFIG_DEFAULTS_H

#include "global.h"

#define DEFAULT_PID_FILE_PATH         "tox-bootstrapd.pid"
#define DEFAULT_KEYS_FILE_PATH        "tox-bootstrapd.keys"
#define DEFAULT_PORT                  33445
#define DEFAULT_ENABLE_IPV6           1 // 1 - true, 0 - false
#define DEFAULT_ENABLE_IPV4_FALLBACK  1 // 1 - true, 0 - false
#define DEFAULT_ENABLE_LAN_DISCOVERY  1 // 1 - true, 0 - false
#define DEFAULT_ENABLE_TCP_RELAY      1 // 1 - true, 0 - false
#define DEFAULT_TCP_RELAY_PORTS       443, 3389, 33445 // comma-separated list of ports. make sure to adjust DEFAULT_TCP_RELAY_PORTS_COUNT accordingly
#define DEFAULT_TCP_RELAY_PORTS_COUNT 3
#define DEFAULT_ENABLE_MOTD           1 // 1 - true, 0 - false
#define DEFAULT_MOTD                  DAEMON_NAME

#endif // CONFIG_DEFAULTS_H
