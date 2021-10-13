/* SPDX-License-Identifier: GPL-3.0-or-later
 * Copyright © 2016-2018 The TokTok team.
 * Copyright © 2015 Tox project.
 */

/*
 * Special bootstrap node only packets.
 *
 * Include it in your bootstrap node and use: bootstrap_set_callbacks() to enable.
 */
#ifndef C_TOXCORE_OTHER_BOOTSTRAP_NODE_PACKETS_H
#define C_TOXCORE_OTHER_BOOTSTRAP_NODE_PACKETS_H

#include "../toxcore/network.h"

#define MAX_MOTD_LENGTH 256 /* I recommend you use a maximum of 96 bytes. The hard maximum is this though. */

int bootstrap_set_callbacks(Networking_Core *net, uint32_t version, uint8_t *motd, uint16_t motd_length);

#endif // C_TOXCORE_OTHER_BOOTSTRAP_NODE_PACKETS_H
