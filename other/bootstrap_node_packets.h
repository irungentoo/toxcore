/* bootstrap_node_packets.h
 *
 * Special bootstrap node only packets.
 *
 * Include it in your bootstrap node and use: bootstrap_set_callbacks() to enable.
 *
 *  Copyright (C) 2015 Tox project All Rights Reserved.
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

#ifndef BOOTSTRAP_NODE_PACKETS_H
#define BOOTSTRAP_NODE_PACKETS_H

#include "../toxcore/network.h"

#define MAX_MOTD_LENGTH 256 /* I recommend you use a maximum of 96 bytes. The hard maximum is this though. */

int bootstrap_set_callbacks(Networking_Core *net, uint32_t version, uint8_t *motd, uint16_t motd_length);

#endif // BOOTSTRAP_NODE_PACKETS_H
